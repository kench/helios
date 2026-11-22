//! The joined Wi-Fi network over nl80211 (LLD 3, section 10.5): for a Wi-Fi interface, the
//! network's SSID and frequency (`NL80211_CMD_GET_INTERFACE`) and the access point's MAC and
//! signal (`NL80211_CMD_GET_STATION`; in station mode the one station is the access point).
//!
//! nl80211 is a generic-netlink family, so its id is looked up first (`CTRL_CMD_GETFAMILY`).
//! Messages are built and parsed here, like rtnetlink's (the owner's choice for the net
//! module), with no `unsafe`. Read-only: nothing here changes the adapter.

use std::io;

use rustix::fd::OwnedFd;
use rustix::net::netlink::{self, SocketAddrNetlink};
use rustix::net::sockopt::{self, Timeout};
use rustix::net::{AddressFamily, SendFlags, SocketType};

use super::netlink::{
    NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, RTA_HDR_LEN, align,
    attributes, invalid, messages, receive, u32_of,
};

const GENL_HDR_LEN: usize = 4;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_STA_INFO_SIGNAL: u16 = 7;
const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;

/// How long one request may take.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// What a Wi-Fi interface is joined to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WifiLink {
    /// The network's name, as UTF-8 (lossy for the rare SSID that isn't).
    pub(crate) ssid: String,
    /// The access point's MAC.
    pub(crate) bssid: Option<[u8; 6]>,
    /// The channel's centre frequency.
    pub(crate) frequency_mhz: Option<u32>,
    /// The received signal, averaged where the driver averages it.
    pub(crate) signal_dbm: Option<i32>,
}

/// Wi-Fi state: the real kernel ([`Nl80211`]), or a test's.
pub(crate) trait Wireless: Send + Sync + 'static {
    /// What interface `index` is joined to; `None` if it isn't joined, or isn't Wi-Fi as far as
    /// nl80211 knows.
    ///
    /// # Errors
    ///
    /// Socket errors, or a reply that doesn't parse.
    fn link(&self, index: u32) -> io::Result<Option<WifiLink>>;
}

/// No Wi-Fi state at all: for tests that don't need it.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoWireless;

#[cfg(test)]
impl Wireless for NoWireless {
    fn link(&self, _index: u32) -> io::Result<Option<WifiLink>> {
        Ok(None)
    }
}

/// The kernel's nl80211, over a `NETLINK_GENERIC` socket per request.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Nl80211;

impl Wireless for Nl80211 {
    fn link(&self, index: u32) -> io::Result<Option<WifiLink>> {
        let socket = open()?;
        let Some(family) = family(&socket)? else {
            // No cfg80211 in this kernel: nothing is Wi-Fi.
            return Ok(None);
        };
        let index_attribute = attribute(NL80211_ATTR_IFINDEX, &index.to_ne_bytes());
        let interface = match request(
            &socket,
            family,
            NL80211_CMD_GET_INTERFACE,
            NLM_F_REQUEST,
            &index_attribute,
        ) {
            Ok(reply) => reply,
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some((ssid, frequency_mhz)) = parse_interface(&interface, family)? else {
            return Ok(None);
        };
        let stations = request(
            &socket,
            family,
            NL80211_CMD_GET_STATION,
            NLM_F_REQUEST | NLM_F_DUMP,
            &index_attribute,
        )?;
        let (bssid, signal_dbm) = parse_station(&stations, family)?;
        Ok(Some(WifiLink {
            ssid,
            bssid,
            frequency_mhz,
            signal_dbm,
        }))
    }
}

fn open() -> io::Result<OwnedFd> {
    let socket = rustix::net::socket(
        AddressFamily::NETLINK,
        SocketType::RAW,
        Some(netlink::GENERIC),
    )?;
    sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(TIMEOUT))?;
    Ok(socket)
}

/// nl80211's family id, or `None` without cfg80211.
fn family(socket: &OwnedFd) -> io::Result<Option<u16>> {
    let mut name = b"nl80211".to_vec();
    name.push(0);
    let reply = match request(
        socket,
        GENL_ID_CTRL,
        CTRL_CMD_GETFAMILY,
        NLM_F_REQUEST,
        &attribute(CTRL_ATTR_FAMILY_NAME, &name),
    ) {
        Ok(reply) => reply,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    parse_family(&reply)
}

/// Sends a generic-netlink request and reads its reply: every datagram up to the one that ends a
/// dump, or the first for a single request. A kernel error is returned as the error.
fn request(
    socket: &OwnedFd,
    family: u16,
    command: u8,
    flags: u16,
    attributes: &[u8],
) -> io::Result<Vec<Vec<u8>>> {
    rustix::net::sendto(
        socket,
        &message(family, flags, command, attributes),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let mut datagrams = Vec::new();
    loop {
        let datagram = receive(socket)?;
        let mut finished = !dump;
        for message in messages(&datagram)? {
            match message.kind {
                NLMSG_ERROR => {
                    let errno = message
                        .payload
                        .get(..4)
                        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                        .ok_or_else(|| invalid("error message too short"))?;
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(errno.saturating_neg()));
                    }
                    finished = true;
                }
                NLMSG_DONE => finished = true,
                _ => {}
            }
        }
        datagrams.push(datagram);
        if finished {
            return Ok(datagrams);
        }
    }
}

/// A generic-netlink message: the netlink header, the generic header, then the attributes.
pub(crate) fn message(family: u16, flags: u16, command: u8, attributes: &[u8]) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + GENL_HDR_LEN + attributes.len();
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_ne_bytes());
    message.extend_from_slice(&family.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&1u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    // struct genlmsghdr: cmd, version, reserved.
    message.extend_from_slice(&[command, 1, 0, 0]);
    message.extend_from_slice(attributes);
    message
}

/// One attribute, padded.
pub(crate) fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = RTA_HDR_LEN + value.len();
    let mut bytes = Vec::with_capacity(align(len));
    bytes.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(align(len), 0);
    bytes
}

/// One reply's attributes: (type, value).
type Reply = Vec<(u16, Vec<u8>)>;

/// The attributes of each message of `family` in `datagrams`.
fn replies(datagrams: &[Vec<u8>], family: u16) -> io::Result<Vec<Reply>> {
    let mut replies = Vec::new();
    for datagram in datagrams {
        for message in messages(datagram)? {
            if message.kind != family {
                continue;
            }
            let body = message
                .payload
                .get(GENL_HDR_LEN..)
                .ok_or_else(|| invalid("generic netlink message too short"))?;
            replies.push(
                attributes(body)?
                    .into_iter()
                    .map(|(kind, value)| (kind, value.to_vec()))
                    .collect(),
            );
        }
    }
    Ok(replies)
}

fn parse_family(datagrams: &[Vec<u8>]) -> io::Result<Option<u16>> {
    Ok(replies(datagrams, GENL_ID_CTRL)?
        .into_iter()
        .flatten()
        .find(|(kind, _)| *kind == CTRL_ATTR_FAMILY_ID)
        .and_then(|(_, value)| <[u8; 2]>::try_from(value.as_slice()).ok())
        .map(u16::from_ne_bytes))
}

/// The SSID and frequency, or `None` if the interface isn't joined to a network.
fn parse_interface(
    datagrams: &[Vec<u8>],
    family: u16,
) -> io::Result<Option<(String, Option<u32>)>> {
    let Some(reply) = replies(datagrams, family)?.into_iter().next() else {
        return Ok(None);
    };
    let ssid = reply
        .iter()
        .find(|(kind, _)| *kind == NL80211_ATTR_SSID)
        .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        .filter(|ssid| !ssid.is_empty());
    let frequency = reply
        .iter()
        .find(|(kind, _)| *kind == NL80211_ATTR_WIPHY_FREQ)
        .and_then(|(_, value)| u32_of(value));
    Ok(ssid.map(|ssid| (ssid, frequency)))
}

/// The access point's MAC and signal: the first station (a station-mode interface has one).
fn parse_station(datagrams: &[Vec<u8>], family: u16) -> io::Result<(Option<[u8; 6]>, Option<i32>)> {
    let Some(reply) = replies(datagrams, family)?.into_iter().next() else {
        return Ok((None, None));
    };
    let bssid = reply
        .iter()
        .find(|(kind, _)| *kind == NL80211_ATTR_MAC)
        .and_then(|(_, value)| <[u8; 6]>::try_from(value.as_slice()).ok());
    let mut signal = None;
    let mut average = None;
    if let Some((_, info)) = reply
        .iter()
        .find(|(kind, _)| *kind == NL80211_ATTR_STA_INFO)
    {
        for (kind, value) in attributes(info)? {
            // dBm as a signed byte.
            let dbm = value.first().map(|&b| i32::from(i8::from_ne_bytes([b])));
            match kind {
                NL80211_STA_INFO_SIGNAL => signal = dbm,
                NL80211_STA_INFO_SIGNAL_AVG => average = dbm,
                _ => {}
            }
        }
    }
    Ok((bssid, average.or(signal)))
}

#[cfg(test)]
mod tests;
