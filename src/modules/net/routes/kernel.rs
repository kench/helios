//! Source routing's netlink side (LLD 3, section 5.4): dumping the rules and routes in Helios's
//! range, and adding and deleting them. Built and parsed in-tree on rustix, like the reads in
//! [`super::super::netlink`]; no `unsafe`. Only ever touches rules at priorities `BASE..LIMIT`
//! and routes in tables `BASE..LIMIT` marked with protocol [`PROTO_HELIOS`].

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, SendFlags, SocketType, sockopt, sockopt::Timeout};

use super::super::netlink::{
    NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDR_LEN, attributes, invalid,
    messages, receive,
};
use super::plan::{BASE, Change, LIMIT, PROTO_HELIOS, Route, Rule, State};

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const AF_INET: u8 = 2;
/// `struct rtmsg` and `struct fib_rule_hdr`: both 12 bytes.
const HEADER_LEN: usize = 12;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;
const FRA_SRC: u16 = 2;
const FRA_PRIORITY: u16 = 6;
const FRA_TABLE: u16 = 15;
const FR_ACT_TO_TBL: u8 = 1;
const RTN_UNICAST: u8 = 1;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const TIMEOUT: Duration = Duration::from_secs(5);

/// The kernel's rules and routes, for [`super`]; a fake in tests.
pub(crate) trait RouteKernel: Send + Sync {
    /// The rules and routes in Helios's range.
    ///
    /// # Errors
    ///
    /// Netlink errors.
    fn current(&self) -> io::Result<State>;

    /// Applies one change.
    ///
    /// # Errors
    ///
    /// Netlink errors, such as `EPERM` without `CAP_NET_ADMIN`.
    fn apply(&self, change: &Change) -> io::Result<()>;
}

/// The real kernel.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Netlink;

impl RouteKernel for Netlink {
    fn current(&self) -> io::Result<State> {
        let mut state = State::default();
        for datagram in dump(RTM_GETRULE)? {
            for message in messages(&datagram)? {
                if message.kind == RTM_NEWRULE
                    && let Some(rule) = parse_rule(message.payload)?
                {
                    state.rules.push(rule);
                }
            }
        }
        for datagram in dump(RTM_GETROUTE)? {
            for message in messages(&datagram)? {
                if message.kind == RTM_NEWROUTE
                    && let Some(route) = parse_route(message.payload)?
                {
                    state.routes.push(route);
                }
            }
        }
        state.rules.sort();
        state.routes.sort();
        Ok(state)
    }

    fn apply(&self, change: &Change) -> io::Result<()> {
        let (kind, flags, body) = match change {
            Change::AddRoute(route) => (
                RTM_NEWROUTE,
                NLM_F_CREATE | NLM_F_REPLACE,
                route_body(route),
            ),
            Change::DeleteRoute(route) => (RTM_DELROUTE, 0, route_body(route)),
            Change::AddRule(rule) => (RTM_NEWRULE, NLM_F_CREATE, rule_body(rule)),
            Change::DeleteRule(rule) => (RTM_DELRULE, 0, rule_body(rule)),
        };
        request(kind, NLM_F_REQUEST | NLM_F_ACK | flags, &body)
    }
}

fn socket() -> io::Result<std::os::fd::OwnedFd> {
    let socket = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)?;
    sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(TIMEOUT))?;
    Ok(socket)
}

/// Sends one request and waits for its acknowledgement.
fn request(kind: u16, flags: u16, body: &[u8]) -> io::Result<()> {
    let socket = socket()?;
    rustix::net::sendto(
        &socket,
        &message(kind, flags, body),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    loop {
        let datagram = receive(&socket)?;
        for message in messages(&datagram)? {
            if message.kind == NLMSG_ERROR {
                return errno(message.payload);
            }
        }
    }
}

/// A dump of IPv4 rules or routes.
fn dump(kind: u16) -> io::Result<Vec<Vec<u8>>> {
    let socket = socket()?;
    let mut header = vec![0u8; HEADER_LEN];
    header[0] = AF_INET;
    rustix::net::sendto(
        &socket,
        &message(kind, NLM_F_REQUEST | NLM_F_DUMP, &header),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    let mut datagrams = Vec::new();
    loop {
        let datagram = receive(&socket)?;
        let mut done = false;
        for message in messages(&datagram)? {
            match message.kind {
                NLMSG_DONE => done = true,
                NLMSG_ERROR => errno(message.payload)?,
                _ => {}
            }
        }
        datagrams.push(datagram);
        if done {
            return Ok(datagrams);
        }
    }
}

/// An `NLMSG_ERROR`'s code: 0 is an acknowledgement.
fn errno(payload: &[u8]) -> io::Result<()> {
    let code = payload
        .get(..4)
        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| invalid("error message too short"))?;
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.saturating_neg()))
    }
}

/// A netlink message: header, then `body`.
pub(crate) fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&1u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out
}

fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize(out.len() + (4 - len % 4) % 4, 0);
}

/// `struct rtmsg` and attributes for `route`.
pub(crate) fn route_body(route: &Route) -> Vec<u8> {
    let scope = if route.gateway.is_some() {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    // family, dst_len, src_len, tos, table (in RTA_TABLE), protocol, scope, type, flags.
    let mut body = vec![
        AF_INET,
        route.destination.1,
        0,
        0,
        0,
        PROTO_HELIOS,
        scope,
        RTN_UNICAST,
    ];
    body.extend_from_slice(&0u32.to_ne_bytes());
    if route.destination.1 > 0 {
        attribute(&mut body, RTA_DST, &route.destination.0.octets());
    }
    attribute(&mut body, RTA_TABLE, &route.table.to_ne_bytes());
    attribute(&mut body, RTA_OIF, &route.interface.to_ne_bytes());
    attribute(&mut body, RTA_PREFSRC, &route.source.octets());
    if let Some(gateway) = route.gateway {
        attribute(&mut body, RTA_GATEWAY, &gateway.octets());
    }
    body
}

/// `struct fib_rule_hdr` and attributes for `rule`.
pub(crate) fn rule_body(rule: &Rule) -> Vec<u8> {
    // family, dst_len, src_len, tos, table (in FRA_TABLE), res1, res2, action, flags.
    let mut body = vec![AF_INET, 0, 32, 0, 0, 0, 0, FR_ACT_TO_TBL];
    body.extend_from_slice(&0u32.to_ne_bytes());
    attribute(&mut body, FRA_SRC, &rule.source.octets());
    attribute(&mut body, FRA_PRIORITY, &rule.priority.to_ne_bytes());
    attribute(&mut body, FRA_TABLE, &rule.table.to_ne_bytes());
    body
}

fn u32_value(value: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(value).ok().map(u32::from_ne_bytes)
}

fn ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from)
}

fn ours(table: u32) -> bool {
    (BASE..LIMIT).contains(&table)
}

/// A rule from a dump, if it's one of Helios's (a /32 source, priority and table in range).
pub(crate) fn parse_rule(payload: &[u8]) -> io::Result<Option<Rule>> {
    if payload.len() < HEADER_LEN {
        return Err(invalid("rule message too short"));
    }
    let (family, src_len, header_table) = (payload[0], payload[2], u32::from(payload[4]));
    let mut source = None;
    let mut priority = None;
    let mut table = header_table;
    for (kind, value) in attributes(&payload[HEADER_LEN..])? {
        match kind {
            FRA_SRC => source = ipv4(value),
            FRA_PRIORITY => priority = u32_value(value),
            FRA_TABLE => table = u32_value(value).unwrap_or(table),
            _ => {}
        }
    }
    Ok(match (family, src_len, source, priority) {
        (AF_INET, 32, Some(source), Some(priority)) if ours(priority) && ours(table) => {
            Some(Rule {
                source,
                priority,
                table,
            })
        }
        _ => None,
    })
}

/// A route from a dump, if it's one of Helios's (protocol `helios`, table in range).
pub(crate) fn parse_route(payload: &[u8]) -> io::Result<Option<Route>> {
    if payload.len() < HEADER_LEN {
        return Err(invalid("route message too short"));
    }
    let (family, dst_len, header_table, protocol) =
        (payload[0], payload[1], u32::from(payload[4]), payload[5]);
    if family != AF_INET || protocol != PROTO_HELIOS {
        return Ok(None);
    }
    let mut table = header_table;
    let (mut destination, mut gateway, mut interface, mut source) =
        (Ipv4Addr::UNSPECIFIED, None, None, None);
    for (kind, value) in attributes(&payload[HEADER_LEN..])? {
        match kind {
            RTA_TABLE => table = u32_value(value).unwrap_or(table),
            RTA_DST => destination = ipv4(value).unwrap_or(destination),
            RTA_GATEWAY => gateway = ipv4(value),
            RTA_OIF => interface = u32_value(value),
            RTA_PREFSRC => source = ipv4(value),
            _ => {}
        }
    }
    Ok(match (interface, source) {
        (Some(interface), Some(source)) if ours(table) => Some(Route {
            table,
            destination: (destination, dst_len),
            gateway,
            interface,
            source,
        }),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi() -> Ipv4Addr {
        "192.168.5.12".parse().unwrap()
    }

    #[test]
    fn rules_round_trip_through_their_messages() {
        let rule = Rule {
            source: wifi(),
            priority: 10_004,
            table: 10_004,
        };
        assert_eq!(parse_rule(&rule_body(&rule)).unwrap(), Some(rule));
        // Not Helios's: another priority, or a rule without a /32 source.
        let other = Rule {
            priority: 32_766,
            ..rule
        };
        assert_eq!(parse_rule(&rule_body(&other)).unwrap(), None);
        let mut any_source = rule_body(&rule);
        any_source[2] = 0;
        assert_eq!(parse_rule(&any_source).unwrap(), None);
        assert!(parse_rule(&[0; 4]).is_err());
    }

    #[test]
    fn routes_round_trip_through_their_messages() {
        let default = Route {
            table: 10_004,
            destination: (Ipv4Addr::UNSPECIFIED, 0),
            gateway: Some("192.168.5.1".parse().unwrap()),
            interface: 4,
            source: wifi(),
        };
        let subnet = Route {
            destination: ("192.168.5.0".parse().unwrap(), 24),
            gateway: None,
            ..default
        };
        for route in [default, subnet] {
            assert_eq!(parse_route(&route_body(&route)).unwrap(), Some(route));
        }
        assert_eq!(route_body(&default)[6], RT_SCOPE_UNIVERSE);
        assert_eq!(route_body(&subnet)[6], RT_SCOPE_LINK);
        // Another protocol (the main table's DHCP routes), or a table out of range.
        let mut dhcp = route_body(&default);
        dhcp[5] = 16;
        assert_eq!(parse_route(&dhcp).unwrap(), None);
        let main = Route {
            table: 254,
            ..default
        };
        assert_eq!(parse_route(&route_body(&main)).unwrap(), None);
        assert!(parse_route(&[0; 3]).is_err());
    }

    #[test]
    fn messages_carry_the_header_and_errors_map() {
        let message = message(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK, &[0; 12]);
        assert_eq!(message.len(), 28);
        assert_eq!(u16::from_ne_bytes([message[4], message[5]]), RTM_NEWRULE);
        assert!(errno(&0i32.to_ne_bytes()).is_ok());
        let eperm = errno(&(-1i32).to_ne_bytes()).unwrap_err();
        assert_eq!(eperm.raw_os_error(), Some(1));
        assert!(errno(&[0]).is_err());
    }
}
