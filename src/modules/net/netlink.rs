//! rtnetlink for the net module (LLD 3, section 2.1): dumps of the links, addresses, default
//! routes and nexthops, and a socket that hears when any of them change.
//!
//! Messages are built and parsed here on rustix, as `identity/bootstrap/netlink.rs` does, so no
//! netlink crate is needed. Nothing here changes the kernel's state: it only reads.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::{self, Timeout};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};

const NLMSG_HDR_LEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const NHMSG_LEN: usize = 8;
const RTA_HDR_LEN: usize = 4;
const RTNEXTHOP_LEN: usize = 8;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWNEXTHOP: u16 = 104;
const RTM_GETNEXTHOP: u16 = 106;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x300;
/// The attribute type's low bits; the top two are the nested and byte-order flags.
const NLA_TYPE_MASK: u16 = 0x3fff;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_CARRIER: u16 = 33;
const IFLA_PERM_ADDRESS: u16 = 54;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_NH_ID: u16 = 30;
const RT_TABLE_MAIN: u32 = 254;
const RTN_UNICAST: u8 = 1;

const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;
const NEXTHOP_GRP_LEN: usize = 8;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `IFF_UP`.
pub(crate) const IFF_UP: u32 = 0x1;
/// `IFF_LOOPBACK`.
pub(crate) const IFF_LOOPBACK: u32 = 0x8;
/// `IFA_F_TEMPORARY`: an IPv6 privacy address.
pub(crate) const IFA_F_TEMPORARY: u32 = 0x01;
/// `IFA_F_DADFAILED`: duplicate address detection found another host using it.
pub(crate) const IFA_F_DADFAILED: u32 = 0x08;
/// `IFA_F_DEPRECATED`: past its preferred lifetime.
pub(crate) const IFA_F_DEPRECATED: u32 = 0x20;
/// `IFA_F_TENTATIVE`: duplicate address detection hasn't finished.
pub(crate) const IFA_F_TENTATIVE: u32 = 0x40;

/// The groups the change socket joins: links, IPv4 and IPv6 addresses and routes
/// (`RTMGRP_LINK`, `RTMGRP_IPV4_IFADDR`, `RTMGRP_IPV4_ROUTE`, `RTMGRP_IPV6_IFADDR`,
/// `RTMGRP_IPV6_ROUTE`). Nexthop changes (group 32, past the bitmask) aren't joined: a nexthop
/// that matters comes and goes with a route, and the module reads everything again then.
const GROUPS: u32 = 0x1 | 0x10 | 0x40 | 0x100 | 0x400;

/// How long the change socket waits before [`Watch::wait`] returns, so its thread can stop.
const WAIT: Duration = Duration::from_secs(1);
/// How long a dump may take.
const DUMP_TIMEOUT: Duration = Duration::from_secs(5);
/// How many times an interrupted dump (the tables changed while it ran) is tried.
const DUMP_TRIES: usize = 3;

/// One link (`RTM_NEWLINK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) index: u32,
    pub(crate) name: String,
    /// `IFF_*`.
    pub(crate) flags: u32,
    pub(crate) mac: Option<Vec<u8>>,
    pub(crate) permanent_mac: Option<Vec<u8>>,
    pub(crate) mtu: Option<u32>,
    /// `IF_OPER_*`.
    pub(crate) oper_state: u8,
    pub(crate) carrier: Option<bool>,
}

/// One address (`RTM_NEWADDR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    pub(crate) index: u32,
    pub(crate) address: IpAddr,
    pub(crate) prefix: u8,
    /// `IFA_F_*`.
    pub(crate) flags: u32,
}

/// One way out of a route: an interface and maybe a gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hop {
    pub(crate) index: u32,
    pub(crate) gateway: Option<IpAddr>,
}

/// How a default route leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Via {
    /// Its own interfaces and gateways (one, or several for a multipath route).
    Hops(Vec<Hop>),
    /// A nexthop object (`RTA_NH_ID`), as networkd and NetworkManager use for IPv6.
    Nexthop(u32),
}

/// A default route in the main table (`RTM_NEWROUTE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) ipv6: bool,
    pub(crate) metric: u32,
    pub(crate) via: Via,
}

/// A nexthop object (`RTM_NEWNEXTHOP`): one hop, or a group of other nexthops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Nexthop {
    pub(crate) id: u32,
    pub(crate) hop: Option<Hop>,
    pub(crate) group: Vec<u32>,
}

/// Everything the module reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Tables {
    pub(crate) links: Vec<Link>,
    pub(crate) addresses: Vec<Address>,
    pub(crate) routes: Vec<Route>,
    pub(crate) nexthops: Vec<Nexthop>,
}

impl Tables {
    /// The interfaces and gateways `route` leaves through.
    pub(crate) fn hops(&self, route: &Route) -> Vec<Hop> {
        match &route.via {
            Via::Hops(hops) => hops.clone(),
            Via::Nexthop(id) => {
                let mut hops = Vec::new();
                self.expand(*id, &mut hops, 0);
                hops
            }
        }
    }

    fn expand(&self, id: u32, hops: &mut Vec<Hop>, depth: usize) {
        // A group holds plain nexthops; the depth limit only guards against a malformed table.
        if depth > 2 {
            return;
        }
        let Some(nexthop) = self.nexthops.iter().find(|nexthop| nexthop.id == id) else {
            return;
        };
        hops.extend(nexthop.hop.clone());
        for member in &nexthop.group {
            self.expand(*member, hops, depth + 1);
        }
    }
}

/// What can be dumped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dump {
    Links,
    Addresses,
    Routes,
    Nexthops,
}

impl Dump {
    const ALL: [Self; 4] = [Self::Links, Self::Addresses, Self::Routes, Self::Nexthops];

    fn request(self) -> (u16, usize) {
        match self {
            Self::Links => (RTM_GETLINK, IFINFOMSG_LEN),
            Self::Addresses => (RTM_GETADDR, IFADDRMSG_LEN),
            Self::Routes => (RTM_GETROUTE, RTMSG_LEN),
            Self::Nexthops => (RTM_GETNEXTHOP, NHMSG_LEN),
        }
    }
}

/// The kernel's routing tables: the real ones ([`Rtnetlink`]), or a test's.
pub(crate) trait Kernel: Send + Sync + 'static {
    /// The reply to one dump request: every datagram, up to and including the one that ends it.
    ///
    /// # Errors
    ///
    /// Socket errors.
    fn dump(&self, dump: Dump) -> io::Result<Vec<Vec<u8>>>;

    /// A socket that hears changes.
    ///
    /// # Errors
    ///
    /// Socket errors.
    fn watch(&self) -> io::Result<Box<dyn Watch>>;
}

/// Hears changes to links, addresses and routes.
pub(crate) trait Watch: Send {
    /// Waits about a second. `true` if anything changed, or if the kernel dropped notifications
    /// (`ENOBUFS`), which means the same: read everything again.
    ///
    /// # Errors
    ///
    /// Socket errors.
    fn wait(&mut self) -> io::Result<bool>;
}

/// Reads every table from `kernel`.
///
/// # Errors
///
/// Socket errors, the kernel's errors, or a reply that doesn't parse.
pub(crate) fn read(kernel: &dyn Kernel) -> io::Result<Tables> {
    let mut tables = Tables::default();
    for dump in Dump::ALL {
        let mut tries = 0;
        loop {
            tries += 1;
            match parse_dump(dump, &kernel.dump(dump)?, &mut tables) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted && tries < DUMP_TRIES => {
                    clear(&mut tables, dump);
                }
                // Kernels without nexthop objects (before 5.3) refuse that dump.
                Err(error)
                    if dump == Dump::Nexthops
                        && matches!(
                            error.raw_os_error(),
                            Some(libc::EINVAL | libc::EOPNOTSUPP | libc::EPROTONOSUPPORT)
                        ) =>
                {
                    break;
                }
                result => break result?,
            }
        }
    }
    Ok(tables)
}

fn clear(tables: &mut Tables, dump: Dump) {
    match dump {
        Dump::Links => tables.links.clear(),
        Dump::Addresses => tables.addresses.clear(),
        Dump::Routes => tables.routes.clear(),
        Dump::Nexthops => tables.nexthops.clear(),
    }
}

/// The real kernel, over `NETLINK_ROUTE` sockets.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Rtnetlink;

impl Kernel for Rtnetlink {
    fn dump(&self, dump: Dump) -> io::Result<Vec<Vec<u8>>> {
        let socket = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
        sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(DUMP_TIMEOUT))?;
        let (kind, header) = dump.request();
        rustix::net::sendto(
            &socket,
            &request(kind, header),
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        let mut datagrams = Vec::new();
        loop {
            let datagram = receive(&socket)?;
            let finished = ends_dump(&datagram);
            datagrams.push(datagram);
            if finished {
                return Ok(datagrams);
            }
        }
    }

    fn watch(&self) -> io::Result<Box<dyn Watch>> {
        let socket = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
        rustix::net::bind(&socket, &SocketAddrNetlink::new(0, GROUPS))?;
        sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(WAIT))?;
        Ok(Box::new(Changes(socket)))
    }
}

struct Changes(OwnedFd);

impl Watch for Changes {
    fn wait(&mut self) -> io::Result<bool> {
        match receive(&self.0) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => Ok(true),
            Err(error) => Err(error),
        }
    }
}

fn receive(socket: &OwnedFd) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 64 * 1024];
    let (read, full) = rustix::net::recv(socket, &mut buffer[..], RecvFlags::empty())?;
    if full > read {
        return Err(invalid("datagram larger than the buffer"));
    }
    buffer.truncate(read);
    Ok(buffer)
}

/// A dump request: the header and a zeroed family header (any family, every interface).
fn request(kind: u16, header: usize) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + header;
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    message.extend_from_slice(&1u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.resize(total, 0);
    message
}

/// One netlink message in a datagram.
struct Message<'a> {
    kind: u16,
    flags: u16,
    payload: &'a [u8],
}

fn messages(datagram: &[u8]) -> io::Result<Vec<Message<'_>>> {
    let mut messages = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        if rest.len() < NLMSG_HDR_LEN {
            return Err(invalid("message shorter than a netlink header"));
        }
        let len = usize::try_from(u32_at(rest, 0)).unwrap_or(usize::MAX);
        if len < NLMSG_HDR_LEN || len > rest.len() {
            return Err(invalid("message length out of range"));
        }
        messages.push(Message {
            kind: u16_at(rest, 4),
            flags: u16_at(rest, 6),
            payload: &rest[NLMSG_HDR_LEN..len],
        });
        rest = &rest[align(len).min(rest.len())..];
    }
    Ok(messages)
}

/// Whether `datagram` ends a dump: it holds `NLMSG_DONE` or an error, or doesn't parse.
fn ends_dump(datagram: &[u8]) -> bool {
    messages(datagram).map_or(true, |messages| {
        messages
            .iter()
            .any(|message| matches!(message.kind, NLMSG_DONE | NLMSG_ERROR))
    })
}

/// Adds one dump's reply to `tables`.
fn parse_dump(dump: Dump, datagrams: &[Vec<u8>], tables: &mut Tables) -> io::Result<()> {
    for datagram in datagrams {
        for message in messages(datagram)? {
            if message.flags & NLM_F_DUMP_INTR != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "rtnetlink: the tables changed during the dump",
                ));
            }
            match (dump, message.kind) {
                (_, NLMSG_DONE) => return Ok(()),
                (_, NLMSG_ERROR) => {
                    let errno = message
                        .payload
                        .get(..4)
                        .map(|bytes| i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                        .ok_or_else(|| invalid("error message too short"))?;
                    if errno == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(errno.saturating_neg()));
                }
                (_, NLMSG_OVERRUN) => return Err(invalid("the kernel's reply overran")),
                (Dump::Links, RTM_NEWLINK) => tables.links.extend(link(message.payload)?),
                (Dump::Addresses, RTM_NEWADDR) => {
                    tables.addresses.extend(address(message.payload)?);
                }
                (Dump::Routes, RTM_NEWROUTE) => tables.routes.extend(route(message.payload)?),
                (Dump::Nexthops, RTM_NEWNEXTHOP) => {
                    tables.nexthops.extend(nexthop(message.payload)?);
                }
                _ => {}
            }
        }
    }
    Err(invalid("dump ended without NLMSG_DONE"))
}

fn link(payload: &[u8]) -> io::Result<Option<Link>> {
    if payload.len() < IFINFOMSG_LEN {
        return Err(invalid("link message too short"));
    }
    let mut link = Link {
        index: u32_at(payload, 4),
        name: String::new(),
        flags: u32_at(payload, 8),
        mac: None,
        permanent_mac: None,
        mtu: None,
        oper_state: 0,
        carrier: None,
    };
    for (kind, value) in attributes(&payload[IFINFOMSG_LEN..])? {
        match kind {
            IFLA_IFNAME => {
                let name = value.split(|&b| b == 0).next().unwrap_or_default();
                link.name = String::from_utf8_lossy(name).into_owned();
            }
            IFLA_ADDRESS => link.mac = hardware_address(value),
            IFLA_PERM_ADDRESS => link.permanent_mac = hardware_address(value),
            IFLA_MTU => link.mtu = u32_of(value),
            IFLA_OPERSTATE => link.oper_state = value.first().copied().unwrap_or(0),
            IFLA_CARRIER => link.carrier = value.first().map(|&carrier| carrier != 0),
            _ => {}
        }
    }
    Ok((!link.name.is_empty()).then_some(link))
}

fn hardware_address(value: &[u8]) -> Option<Vec<u8>> {
    (!value.is_empty() && value.iter().any(|&b| b != 0)).then(|| value.to_vec())
}

fn address(payload: &[u8]) -> io::Result<Option<Address>> {
    if payload.len() < IFADDRMSG_LEN {
        return Err(invalid("address message too short"));
    }
    let family = payload[0];
    let prefix = payload[1];
    let mut flags = u32::from(payload[2]);
    let index = u32_at(payload, 4);
    let (mut address, mut local) = (None, None);
    for (kind, value) in attributes(&payload[IFADDRMSG_LEN..])? {
        match kind {
            IFA_ADDRESS => address = ip(family, value),
            IFA_LOCAL => local = ip(family, value),
            IFA_FLAGS => flags = u32_of(value).unwrap_or(flags),
            _ => {}
        }
    }
    // On a point-to-point link IFA_ADDRESS is the far end; the interface's own is IFA_LOCAL.
    Ok(local.or(address).map(|address| Address {
        index,
        address,
        prefix,
        flags,
    }))
}

fn route(payload: &[u8]) -> io::Result<Option<Route>> {
    if payload.len() < RTMSG_LEN {
        return Err(invalid("route message too short"));
    }
    let family = payload[0];
    let destination_len = payload[1];
    let mut table = u32::from(payload[4]);
    let kind = payload[7];
    let (mut index, mut gateway, mut metric, mut nexthop, mut multipath) =
        (None, None, 0, None, Vec::new());
    for (attribute, value) in attributes(&payload[RTMSG_LEN..])? {
        match attribute {
            RTA_TABLE => table = u32_of(value).unwrap_or(table),
            RTA_OIF => index = u32_of(value),
            RTA_GATEWAY => gateway = ip(family, value),
            RTA_VIA => gateway = via(value),
            RTA_PRIORITY => metric = u32_of(value).unwrap_or(0),
            RTA_NH_ID => nexthop = u32_of(value),
            RTA_MULTIPATH => multipath = hops(family, value)?,
            _ => {}
        }
    }
    if destination_len != 0
        || table != RT_TABLE_MAIN
        || kind != RTN_UNICAST
        || !matches!(family, AF_INET | AF_INET6)
    {
        return Ok(None);
    }
    let via = match (nexthop, index) {
        (Some(id), _) => Via::Nexthop(id),
        (None, Some(index)) => Via::Hops(vec![Hop { index, gateway }]),
        (None, None) if !multipath.is_empty() => Via::Hops(multipath),
        (None, None) => return Ok(None),
    };
    Ok(Some(Route {
        ipv6: family == AF_INET6,
        metric,
        via,
    }))
}

/// A multipath route's `struct rtnexthop` list.
fn hops(family: u8, mut value: &[u8]) -> io::Result<Vec<Hop>> {
    let mut hops = Vec::new();
    while value.len() >= RTNEXTHOP_LEN {
        let len = usize::from(u16_at(value, 0));
        if len < RTNEXTHOP_LEN || len > value.len() {
            return Err(invalid("multipath hop length out of range"));
        }
        let mut gateway = None;
        for (attribute, attribute_value) in attributes(&value[RTNEXTHOP_LEN..len])? {
            match attribute {
                RTA_GATEWAY => gateway = ip(family, attribute_value),
                RTA_VIA => gateway = via(attribute_value),
                _ => {}
            }
        }
        hops.push(Hop {
            index: u32_at(value, 4),
            gateway,
        });
        value = &value[align(len).min(value.len())..];
    }
    Ok(hops)
}

/// `struct rtvia`: a gateway of another family (an IPv4 route through an IPv6 router).
fn via(value: &[u8]) -> Option<IpAddr> {
    let family = value
        .get(..2)
        .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))?;
    ip(u8::try_from(family).ok()?, &value[2..])
}

fn nexthop(payload: &[u8]) -> io::Result<Option<Nexthop>> {
    if payload.len() < NHMSG_LEN {
        return Err(invalid("nexthop message too short"));
    }
    let family = payload[0];
    let (mut id, mut index, mut gateway, mut group) = (None, None, None, Vec::new());
    for (kind, value) in attributes(&payload[NHMSG_LEN..])? {
        match kind {
            NHA_ID => id = u32_of(value),
            NHA_OIF => index = u32_of(value),
            NHA_GATEWAY => gateway = ip(family, value),
            NHA_GROUP => {
                group = value
                    .as_chunks::<NEXTHOP_GRP_LEN>()
                    .0
                    .iter()
                    .map(|member| u32_at(member, 0))
                    .collect();
            }
            _ => {}
        }
    }
    Ok(id.map(|id| Nexthop {
        id,
        hop: index.map(|index| Hop { index, gateway }),
        group,
    }))
}

fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut attributes = Vec::new();
    while bytes.len() >= RTA_HDR_LEN {
        let len = usize::from(u16_at(bytes, 0));
        if len < RTA_HDR_LEN || len > bytes.len() {
            return Err(invalid("attribute length out of range"));
        }
        attributes.push((u16_at(bytes, 2) & NLA_TYPE_MASK, &bytes[RTA_HDR_LEN..len]));
        bytes = &bytes[align(len).min(bytes.len())..];
    }
    Ok(attributes)
}

fn ip(family: u8, value: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET => <[u8; 4]>::try_from(value)
            .ok()
            .map(|bytes| IpAddr::V4(Ipv4Addr::from(bytes))),
        AF_INET6 => <[u8; 16]>::try_from(value)
            .ok()
            .map(|bytes| IpAddr::V6(Ipv6Addr::from(bytes))),
        _ => None,
    }
}

fn u32_of(value: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(value).ok().map(u32::from_ne_bytes)
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

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("rtnetlink: {what}"))
}

/// Builds the kernel's messages, for tests here and in the module.
#[cfg(test)]
pub(crate) mod build {
    use super::*;

    /// A netlink message.
    pub(crate) fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        let len = u32::try_from(NLMSG_HDR_LEN + body.len()).unwrap();
        message.extend_from_slice(&len.to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&1u32.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        message.resize(align(message.len()), 0);
        message
    }

    /// `NLMSG_DONE`.
    pub(crate) fn done() -> Vec<u8> {
        message(NLMSG_DONE, 0x2, &0u32.to_ne_bytes())
    }

    /// `NLMSG_ERROR` with `errno` (positive).
    pub(crate) fn error(errno: i32) -> Vec<u8> {
        let mut body = (-errno).to_ne_bytes().to_vec();
        body.extend_from_slice(&[0; NLMSG_HDR_LEN]);
        message(NLMSG_ERROR, 0, &body)
    }

    /// Attributes after a fixed header.
    pub(crate) fn with_attributes(mut body: Vec<u8>, attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
        for (kind, value) in attributes {
            let len = RTA_HDR_LEN + value.len();
            body.extend_from_slice(&u16::try_from(len).unwrap().to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(value);
            body.resize(align(body.len()), 0);
        }
        body
    }

    /// An `RTM_NEWLINK`.
    pub(crate) fn link(
        index: u32,
        name: &str,
        flags: u32,
        mac: Option<[u8; 6]>,
        oper_state: u8,
        carrier: bool,
    ) -> Vec<u8> {
        let mut header = vec![0u8; IFINFOMSG_LEN];
        header[4..8].copy_from_slice(&index.to_ne_bytes());
        header[8..12].copy_from_slice(&flags.to_ne_bytes());
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        let mut attributes = vec![
            (IFLA_IFNAME, name),
            (IFLA_MTU, 1500u32.to_ne_bytes().to_vec()),
            (IFLA_OPERSTATE, vec![oper_state]),
            (IFLA_CARRIER, vec![u8::from(carrier)]),
        ];
        if let Some(mac) = mac {
            attributes.push((IFLA_ADDRESS, mac.to_vec()));
        }
        message(RTM_NEWLINK, 0x2, &with_attributes(header, &attributes))
    }

    /// An `RTM_NEWADDR`.
    pub(crate) fn address(index: u32, address: IpAddr, prefix: u8, flags: u32) -> Vec<u8> {
        let (family, bytes) = family_bytes(address);
        let mut header = vec![family, prefix, 0, 0];
        header.extend_from_slice(&index.to_ne_bytes());
        let attributes = [
            (IFA_ADDRESS, bytes),
            (IFA_FLAGS, flags.to_ne_bytes().to_vec()),
        ];
        message(RTM_NEWADDR, 0x2, &with_attributes(header, &attributes))
    }

    /// A main-table default route out of `index`, or through nexthop `nexthop`.
    pub(crate) fn default_route(
        ipv6: bool,
        index: Option<u32>,
        gateway: Option<IpAddr>,
        metric: u32,
        nexthop: Option<u32>,
    ) -> Vec<u8> {
        let family = if ipv6 { AF_INET6 } else { AF_INET };
        let header = vec![family, 0, 0, 0, 254, 3, 0, RTN_UNICAST, 0, 0, 0, 0];
        let mut attributes = vec![
            (RTA_TABLE, RT_TABLE_MAIN.to_ne_bytes().to_vec()),
            (RTA_PRIORITY, metric.to_ne_bytes().to_vec()),
        ];
        if let Some(index) = index {
            attributes.push((RTA_OIF, index.to_ne_bytes().to_vec()));
        }
        if let Some(gateway) = gateway {
            attributes.push((RTA_GATEWAY, family_bytes(gateway).1));
        }
        if let Some(id) = nexthop {
            attributes.push((RTA_NH_ID, id.to_ne_bytes().to_vec()));
        }
        message(RTM_NEWROUTE, 0x2, &with_attributes(header, &attributes))
    }

    /// An `RTM_NEWNEXTHOP` with one hop.
    pub(crate) fn nexthop(id: u32, index: u32, gateway: IpAddr) -> Vec<u8> {
        let (family, bytes) = family_bytes(gateway);
        let header = vec![family, 0, 0, 0, 0, 0, 0, 0];
        let attributes = [
            (NHA_ID, id.to_ne_bytes().to_vec()),
            (NHA_OIF, index.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, bytes),
        ];
        message(RTM_NEWNEXTHOP, 0x2, &with_attributes(header, &attributes))
    }

    pub(crate) fn family_bytes(address: IpAddr) -> (u8, Vec<u8>) {
        match address {
            IpAddr::V4(address) => (AF_INET, address.octets().to_vec()),
            IpAddr::V6(address) => (AF_INET6, address.octets().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests;
