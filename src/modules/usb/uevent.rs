use std::io;
use std::os::fd::OwnedFd;

use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{self, AddressFamily, RecvFlags, SocketFlags, SocketType};
use tokio::io::unix::AsyncFd;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Uevent {
    pub action: String,
    pub path: String,
    pub subsystem: String,
    pub device_type: String,
    pub old_path: Option<String>,
    pub sequence: Option<u64>,
}

pub(crate) fn parse(bytes: &[u8], sender: u32) -> Option<Uevent> {
    if sender != 0 || bytes.len() > 2048 {
        return None;
    }
    let mut fields = std::str::from_utf8(bytes)
        .ok()?
        .trim_end_matches('\0')
        .split('\0');
    let (action, path) = fields.next()?.split_once('@')?;
    let mut event = Uevent {
        action: String::new(),
        path: String::new(),
        subsystem: String::new(),
        device_type: String::new(),
        old_path: None,
        sequence: None,
    };
    for field in fields {
        let (key, value) = field.split_once('=')?;
        match key {
            "ACTION" => event.action = value.into(),
            "DEVPATH" => event.path = value.into(),
            "SUBSYSTEM" => event.subsystem = value.into(),
            "DEVTYPE" => event.device_type = value.into(),
            "DEVPATH_OLD" => event.old_path = Some(value.into()),
            "SEQNUM" => event.sequence = Some(value.parse().ok()?),
            _ => {}
        }
    }
    (event.action == action && event.path == path && path.starts_with("/devices/")).then_some(event)
}

pub(crate) struct Datagram {
    pub bytes: Vec<u8>,
    pub sender: u32,
}

pub(crate) trait UeventSource {
    fn receive(&mut self) -> impl Future<Output = io::Result<Datagram>> + Send;
}

pub(crate) struct Socket(AsyncFd<OwnedFd>);

impl Socket {
    /// Opens the kernel's uevent socket (netlink group 1), non-blocking, with a 1 MiB receive
    /// buffer so a hub enumerating several devices doesn't overflow it.
    pub(crate) fn open() -> io::Result<Self> {
        let fd = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(net::netlink::KOBJECT_UEVENT),
        )?;
        net::sockopt::set_socket_recv_buffer_size(&fd, 1024 * 1024)?;
        net::bind(&fd, &SocketAddrNetlink::new(0, 1))?;
        Ok(Self(register(fd)?))
    }
}

/// Registers the socket with tokio's reactor. One of Helios's two approved `unsafe` sites (with
/// `mounts::register`, owner's OK on 2026-11-21): tokio 1.54 deprecated the safe-looking
/// `AsyncFd::new` as unsound and made the replacement an `unsafe fn`.
#[allow(unsafe_code)]
fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: the `AsyncFd` takes ownership of `fd`, an `OwnedFd`, so the descriptor stays open
    // and refers to the same socket until the `AsyncFd` is dropped, and `as_raw_fd` always
    // returns that same descriptor. Nothing else can close it, as nothing else owns it.
    unsafe { AsyncFd::register_with_interest(fd, tokio::io::Interest::READABLE) }
        .map_err(io::Error::from)
}

impl UeventSource for Socket {
    async fn receive(&mut self) -> io::Result<Datagram> {
        self.0
            .async_io(tokio::io::Interest::READABLE, |fd| {
                let mut buffer = [0; 8192];
                let (copied, _, sender) = net::recvfrom(fd, &mut buffer[..], RecvFlags::TRUNC)?;
                let sender = sender.and_then(|addr| SocketAddrNetlink::try_from(addr).ok());
                Ok(Datagram {
                    bytes: buffer[..copied].to_vec(),
                    sender: sender.map_or(u32::MAX, |addr| addr.pid()),
                })
            })
            .await
    }
}
