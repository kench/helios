//! Every interface's IPv4 addresses, over rtnetlink (one `RTM_GETADDR` dump), for the srtla
//! uplink list (LLD 4, section 5.2), until the net module (LLD 3) provides it. Built and parsed
//! here, like the identity code's `RTM_GETLINK`, so no netlink crate is needed.

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};

const NLMSG_HDR_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTA_HDR_LEN: usize = 4;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const AF_INET: u8 = 2;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

/// One IPv4 address and the interface it's on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Address {
    pub interface: String,
    pub address: Ipv4Addr,
    /// Whether the interface is one of the board's own ports, for `net:ethernet` and
    /// `net:wifi`.
    pub onboard: Option<Onboard>,
}

/// A port of the board itself (PCIe or platform, not USB), from sysfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Onboard {
    Ethernet,
    Wifi,
}

impl Onboard {
    /// The kind of the interface `name` under `sysfs` (`/sys`), if it's the board's own: it has
    /// a device that isn't below a USB hub, and it's Wi-Fi (`wireless` or `phy80211`) or
    /// Ethernet (`type` 1, not a cellular modem). Bridges, tunnels, WireGuard and `veth` have
    /// no device, so they're never onboard.
    pub(crate) fn of(sysfs: &Path, name: &str) -> Option<Self> {
        let dir = sysfs.join("class/net").join(name);
        let device = std::fs::canonicalize(dir.join("device")).ok()?;
        if crate::sysfs::on_usb(&device) {
            return None;
        }
        if dir.join("wireless").exists() || dir.join("phy80211").exists() {
            return Some(Self::Wifi);
        }
        let wwan = crate::sysfs::read_attr(&dir.join("uevent"))
            .is_some_and(|uevent| uevent.lines().any(|line| line == "DEVTYPE=wwan"));
        (!wwan && crate::sysfs::read_attr(&dir.join("type")).as_deref() == Some("1"))
            .then_some(Self::Ethernet)
    }
}

/// Every IPv4 address on the system, by interface label.
///
/// # Errors
///
/// Socket errors, or the kernel's error for the dump.
pub(crate) fn ipv4_addresses() -> io::Result<Vec<Address>> {
    let socket = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
    rustix::net::sendto(
        &socket,
        &getaddr_request(),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    let mut addresses = Vec::new();
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let (_, len) = rustix::net::recv(&socket, &mut buffer[..], RecvFlags::empty())?;
        let reply = buffer
            .get(..len)
            .ok_or_else(|| invalid("reply truncated"))?;
        if parse_dump(reply, &mut addresses)? {
            for address in &mut addresses {
                // An alias (eth0:1) is a port's if its interface is.
                let name = address.interface.split(':').next().unwrap_or_default();
                address.onboard = Onboard::of(Path::new("/sys"), name);
            }
            addresses.sort();
            addresses.dedup();
            return Ok(addresses);
        }
    }
}

/// An `RTM_GETADDR` dump request for IPv4.
fn getaddr_request() -> Vec<u8> {
    let total = NLMSG_HDR_LEN + IFADDRMSG_LEN;
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_ne_bytes());
    message.extend_from_slice(&RTM_GETADDR.to_ne_bytes());
    message.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    message.extend_from_slice(&1u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    // struct ifaddrmsg: family AF_INET, the rest zero.
    message.push(AF_INET);
    message.resize(total, 0);
    message
}

/// Adds the addresses in one datagram of the dump; `true` once the dump is done.
pub(crate) fn parse_dump(mut reply: &[u8], addresses: &mut Vec<Address>) -> io::Result<bool> {
    while reply.len() >= NLMSG_HDR_LEN {
        let len = usize::try_from(u32_at(reply, 0)).unwrap_or(usize::MAX);
        let kind = u16_at(reply, 4);
        if len < NLMSG_HDR_LEN || len > reply.len() {
            return Err(invalid("message length out of range"));
        }
        let message = &reply[..len];
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let payload = message
                    .get(NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4)
                    .ok_or_else(|| invalid("error reply too short"))?;
                let errno = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno.saturating_neg()));
                }
            }
            RTM_NEWADDR => {
                if let Some(address) = parse_address(message)? {
                    addresses.push(address);
                }
            }
            _ => {}
        }
        let next = align(len).min(reply.len());
        reply = &reply[next..];
    }
    Ok(false)
}

fn parse_address(message: &[u8]) -> io::Result<Option<Address>> {
    let header = message
        .get(NLMSG_HDR_LEN..NLMSG_HDR_LEN + IFADDRMSG_LEN)
        .ok_or_else(|| invalid("address message too short"))?;
    if header[0] != AF_INET {
        return Ok(None);
    }
    let mut attributes = &message[NLMSG_HDR_LEN + IFADDRMSG_LEN..];
    let (mut local, mut address, mut label) = (None, None, None);
    while attributes.len() >= RTA_HDR_LEN {
        let attribute_len = usize::from(u16_at(attributes, 0));
        let attribute_type = u16_at(attributes, 2);
        if attribute_len < RTA_HDR_LEN || attribute_len > attributes.len() {
            return Err(invalid("attribute length out of range"));
        }
        let value = &attributes[RTA_HDR_LEN..attribute_len];
        match attribute_type {
            IFA_LOCAL => local = <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from),
            IFA_ADDRESS => address = <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from),
            IFA_LABEL => {
                label = std::str::from_utf8(value)
                    .ok()
                    .map(|text| text.trim_end_matches('\0').to_owned());
            }
            _ => {}
        }
        let next = align(attribute_len).min(attributes.len());
        attributes = &attributes[next..];
    }
    // IFA_LOCAL is the interface's own address; IFA_ADDRESS is the peer's on point-to-point
    // links, and the same as IFA_LOCAL otherwise.
    Ok(local
        .or(address)
        .zip(label)
        .map(|(address, interface)| Address {
            interface,
            address,
            onboard: None,
        }))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

const fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
