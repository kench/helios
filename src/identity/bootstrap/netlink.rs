//! Reads an interface's permanent MAC address (`IFLA_PERM_ADDRESS`) over rtnetlink.
//!
//! One `RTM_GETLINK` request by interface name, built and parsed here so no netlink crate is
//! needed. Kernels before 5.6, and drivers that don't report a permanent address, leave the
//! attribute out.

use std::io;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};

use crate::identity::bootstrap::adapters::MacAddress;

const NLMSG_HDR_LEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const RTA_HDR_LEN: usize = 4;

const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const NLM_F_REQUEST: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_PERM_ADDRESS: u16 = 54;

/// The sequence number of the one request on each socket.
const SEQUENCE: u32 = 1;

/// Asks the kernel for `interface`'s permanent MAC address. `Ok(None)` if the kernel or driver
/// doesn't report one, or reports all zeros.
///
/// # Errors
///
/// Socket errors, or the kernel's error for the request (`ENODEV` for an unknown interface).
pub(crate) fn permanent_address(interface: &str) -> io::Result<Option<MacAddress>> {
    let socket = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
    let kernel = SocketAddrNetlink::new(0, 0);
    let request = getlink_request(interface)?;
    rustix::net::sendto(&socket, &request, SendFlags::empty(), &kernel)?;
    let mut buffer = vec![0u8; 32 * 1024];
    let (_, len) = rustix::net::recv(&socket, &mut buffer[..], RecvFlags::empty())?;
    let reply = buffer
        .get(..len)
        .ok_or_else(|| invalid("reply truncated"))?;
    parse_reply(reply)
}

/// An `RTM_GETLINK` request for the interface named `interface`.
fn getlink_request(interface: &str) -> io::Result<Vec<u8>> {
    if interface.is_empty() || interface.len() > 15 || interface.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {interface:?}"),
        ));
    }
    let name_len = interface.len() + 1;
    let attribute_len = RTA_HDR_LEN + name_len;
    let total = NLMSG_HDR_LEN + IFINFOMSG_LEN + align(attribute_len);
    let mut message = Vec::with_capacity(total);
    // struct nlmsghdr
    message.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_ne_bytes());
    message.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
    message.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    message.extend_from_slice(&SEQUENCE.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    // struct ifinfomsg: any family, index 0 (look up by name).
    message.extend_from_slice(&[0u8; IFINFOMSG_LEN]);
    // struct rtattr IFLA_IFNAME, NUL-terminated.
    message.extend_from_slice(
        &u16::try_from(attribute_len)
            .unwrap_or(u16::MAX)
            .to_ne_bytes(),
    );
    message.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
    message.extend_from_slice(interface.as_bytes());
    message.push(0);
    message.resize(total, 0);
    Ok(message)
}

/// Finds `IFLA_PERM_ADDRESS` in an `RTM_NEWLINK` reply, or the error in an `NLMSG_ERROR`.
fn parse_reply(reply: &[u8]) -> io::Result<Option<MacAddress>> {
    let header = reply
        .get(..NLMSG_HDR_LEN)
        .ok_or_else(|| invalid("reply shorter than a netlink header"))?;
    let len = usize::try_from(u32_at(header, 0)).unwrap_or(usize::MAX);
    let kind = u16_at(header, 4);
    let message = reply
        .get(..len)
        .filter(|_| len >= NLMSG_HDR_LEN)
        .ok_or_else(|| invalid("reply length out of range"))?;
    match kind {
        NLMSG_ERROR => {
            let payload = message
                .get(NLMSG_HDR_LEN..NLMSG_HDR_LEN + 4)
                .ok_or_else(|| invalid("error reply too short"))?;
            let errno = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Err(io::Error::from_raw_os_error(errno.saturating_neg()))
        }
        RTM_NEWLINK => {
            let mut attributes = message
                .get(NLMSG_HDR_LEN + IFINFOMSG_LEN..)
                .ok_or_else(|| invalid("link reply too short"))?;
            while attributes.len() >= RTA_HDR_LEN {
                let attribute_len = usize::from(u16_at(attributes, 0));
                let attribute_type = u16_at(attributes, 2);
                if attribute_len < RTA_HDR_LEN || attribute_len > attributes.len() {
                    return Err(invalid("attribute length out of range"));
                }
                if attribute_type == IFLA_PERM_ADDRESS {
                    let value = &attributes[RTA_HDR_LEN..attribute_len];
                    return Ok(<[u8; 6]>::try_from(value)
                        .ok()
                        .map(MacAddress::new)
                        .filter(|mac| !mac.is_zero()));
                }
                let next = align(attribute_len).min(attributes.len());
                attributes = &attributes[next..];
            }
            Ok(None)
        }
        other => Err(invalid(&format!("unexpected netlink message type {other}"))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An `RTM_NEWLINK` reply with the given attributes.
    fn newlink(attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![0u8; IFINFOMSG_LEN];
        for (kind, value) in attributes {
            let len = RTA_HDR_LEN + value.len();
            body.extend_from_slice(&u16::try_from(len).unwrap().to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(value);
            body.resize(align(body.len()), 0);
        }
        message(RTM_NEWLINK, &body)
    }

    fn message(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut message = Vec::new();
        let len = u32::try_from(NLMSG_HDR_LEN + body.len()).unwrap();
        message.extend_from_slice(&len.to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&0u16.to_ne_bytes());
        message.extend_from_slice(&SEQUENCE.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        message
    }

    #[test]
    fn builds_a_getlink_request_by_name() {
        let request = getlink_request("wlan0").unwrap();

        // Header, ifinfomsg, then a 4-byte attribute header and "wlan0\0" padded to 12.
        assert_eq!(request.len(), 16 + 16 + 12);
        assert_eq!(u32_at(&request, 0), 44);
        assert_eq!(u16_at(&request, 4), RTM_GETLINK);
        assert_eq!(u16_at(&request, 6), NLM_F_REQUEST);
        assert_eq!(u16_at(&request, 32), 10);
        assert_eq!(u16_at(&request, 34), IFLA_IFNAME);
        assert_eq!(&request[36..42], b"wlan0\0");
        assert_eq!(&request[42..], [0, 0]);
    }

    #[test]
    fn rejects_invalid_interface_names() {
        for name in ["", "a-name-that-is-too-long", "eth\u{0}0"] {
            let error = getlink_request(name).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
    }

    #[test]
    fn finds_the_permanent_address_among_other_attributes() {
        let mac = [0x2c, 0xcf, 0x67, 0x00, 0x00, 0x01];
        let reply = newlink(&[
            (IFLA_IFNAME, b"eth0\0"),
            (1, &[0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
            (IFLA_PERM_ADDRESS, &mac),
        ]);

        assert_eq!(parse_reply(&reply).unwrap(), Some(MacAddress::new(mac)));
    }

    #[test]
    fn a_missing_or_zero_address_is_none() {
        assert_eq!(
            parse_reply(&newlink(&[(IFLA_IFNAME, b"lo\0")])).unwrap(),
            None
        );
        assert_eq!(
            parse_reply(&newlink(&[(IFLA_PERM_ADDRESS, &[0; 6])])).unwrap(),
            None
        );
        // Not an Ethernet address (for example a 20-byte InfiniBand one).
        assert_eq!(
            parse_reply(&newlink(&[(IFLA_PERM_ADDRESS, &[1; 20])])).unwrap(),
            None
        );
    }

    #[test]
    fn reports_kernel_errors() {
        let errno = -19i32; // ENODEV
        let reply = message(NLMSG_ERROR, &errno.to_ne_bytes());

        let error = parse_reply(&reply).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(19));
    }

    #[test]
    fn rejects_malformed_replies() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0; 8],
            {
                let mut reply = newlink(&[]);
                reply[0] = 200;
                reply
            },
            message(NLMSG_ERROR, &[0, 0]),
            message(RTM_NEWLINK, &[0; 4]),
            message(3, &[]),
            {
                let mut reply = newlink(&[(IFLA_IFNAME, b"eth0\0")]);
                // Attribute length beyond the message.
                reply[32] = 200;
                reply
            },
            {
                let mut reply = newlink(&[(IFLA_IFNAME, b"eth0\0")]);
                reply[32] = 2;
                reply[33] = 0;
                reply
            },
        ];
        for reply in cases {
            let error = parse_reply(&reply).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{reply:?}");
        }
    }

    #[test]
    fn asks_the_kernel() {
        // The loopback interface exists everywhere and has no permanent address.
        assert_eq!(permanent_address("lo").unwrap(), None);
        let error = permanent_address("helios-none0").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(19), "{error}");
    }
}
