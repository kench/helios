//! Whether the MQTT connection's local address still exists. When the uplink carrying the
//! connection goes away (an Ethernet cable pulled), the TCP socket stays established on an
//! address the host no longer has, and nothing on it fails until the keepalive gives up: up to
//! one and a half keepalives (90 seconds by default) with the cloud seeing stale state. The
//! manager checks the address every few seconds instead, and reconnects over another uplink as
//! soon as it's gone.
//!
//! `rumqttc` doesn't expose its socket, so the connection is found in `/proc/self/net/tcp{,6}`:
//! an established socket of this process to the endpoint's port and one of its addresses. An
//! address exists if a UDP socket can bind to it (`EADDRNOTAVAIL` otherwise).

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// How the manager watches its connection's local address. Tests replace the lookups.
#[derive(Debug, Clone, Copy)]
pub struct AddressWatch {
    /// How often the address is checked while connected.
    pub interval: Duration,
    /// The local address of this process's connection to one of `remotes` on `port`.
    pub find: fn(remotes: &[IpAddr], port: u16) -> Option<IpAddr>,
    /// Whether the host still has `address`.
    pub exists: fn(address: IpAddr) -> bool,
}

impl Default for AddressWatch {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
            find: connection_local,
            exists: address_exists,
        }
    }
}

/// One line of `/proc/net/tcp` or `tcp6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
    pub(crate) established: bool,
    pub(crate) inode: u64,
}

/// The local address of this process's established TCP connection to one of `remotes` on
/// `port`, if there is one.
#[must_use]
pub fn connection_local(remotes: &[IpAddr], port: u16) -> Option<IpAddr> {
    let inodes = socket_inodes();
    ["/proc/self/net/tcp", "/proc/self/net/tcp6"]
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .flat_map(|text| parse(&text))
        .find(|entry| {
            entry.established
                && inodes.contains(&entry.inode)
                && entry.remote.port() == port
                && remotes.contains(&canonical(entry.remote.ip()))
        })
        .map(|entry| canonical(entry.local.ip()))
}

/// Whether the host has `address`: binding to an address it doesn't have fails with
/// `EADDRNOTAVAIL`. Any other error counts as present, so a doubt never drops a connection.
#[must_use]
pub fn address_exists(address: IpAddr) -> bool {
    match UdpSocket::bind(SocketAddr::new(address, 0)) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::AddrNotAvailable,
    }
}

/// The inodes of this process's sockets, from its file descriptors (`socket:[<inode>]`).
fn socket_inodes() -> HashSet<u64> {
    std::fs::read_dir("/proc/self/fd")
        .into_iter()
        .flatten()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

/// The entries of a `/proc/net/tcp` or `tcp6` table, skipping its header and anything
/// malformed.
pub(crate) fn parse(text: &str) -> Vec<Entry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(Entry {
                local: socket_address(fields.get(1)?)?,
                remote: socket_address(fields.get(2)?)?,
                // TCP_ESTABLISHED.
                established: *fields.get(3)? == "01",
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// `0100007F:22B3` (127.0.0.1:8883). The kernel prints each 32-bit word of the address in host
/// byte order, which is little-endian on every board Helios runs on.
fn socket_address(text: &str) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |hex: &str| u32::from_str_radix(hex, 16).ok().map(u32::to_le_bytes);
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(address)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for (index, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *chunk = word(address.get(index * 8..index * 8 + 8)?)?;
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// An IPv4-mapped IPv6 address (a v4 connection on a v6 socket) as plain IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   102        0 1001 1 0000000000000000 100 0 0 10 0
   1: 1F05A8C0:D2F4 0A7100CB:22B3 01 00000000:00000000 02:000A0B4E 00000000  1000        0 2002 2 0000000000000000 21 4 30 10 -1
   2: garbage
";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000C05A8C0:C350 0000000000000000FFFF00000A7100CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 3003 1 0000000000000000 20 4 0 10 -1
   1: B80D01200000000000000000FF000000:A000 B80D01200000000000000000EE000000:22B3 01 00000000:00000000 00:00000000 00000000  1000        0 4004 1 0000000000000000 20 4 0 10 -1
";

    #[test]
    fn reads_ipv4_entries() {
        let entries = parse(TCP);
        assert_eq!(
            entries.len(),
            2,
            "the header and the malformed line are skipped"
        );
        assert_eq!(entries[0].local, "127.0.0.1:53".parse().unwrap());
        assert!(!entries[0].established, "0A is LISTEN");
        assert_eq!(
            entries[1],
            Entry {
                local: "192.168.5.31:54004".parse().unwrap(),
                remote: "203.0.113.10:8883".parse().unwrap(),
                established: true,
                inode: 2002,
            }
        );
    }

    #[test]
    fn reads_ipv6_and_mapped_entries() {
        let entries = parse(TCP6);
        assert_eq!(
            canonical(entries[0].local.ip()),
            "192.168.5.12".parse::<IpAddr>().unwrap()
        );
        assert_eq!(entries[0].remote.port(), 443);
        assert_eq!(entries[1].local, "[2001:db8::ff]:40960".parse().unwrap());
        assert_eq!(entries[1].remote, "[2001:db8::ee]:8883".parse().unwrap());
        assert_eq!(entries[1].inode, 4004);
    }

    #[test]
    fn knows_which_addresses_exist() {
        assert!(address_exists(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        // TEST-NET-1: no host has it.
        assert!(!address_exists("192.0.2.123".parse().unwrap()));
    }

    #[test]
    fn finds_its_own_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(connection_local(&[localhost], port), Some(localhost));
        assert_eq!(
            connection_local(&["192.0.2.1".parse().unwrap()], port),
            None,
            "another remote address"
        );
    }
}
