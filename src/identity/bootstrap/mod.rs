//! Bootstrap: the token PIN and device identity from the bootstrap service, looked up by the
//! permanent MAC addresses of the device's built-in network adapters (LLD 1, section 4.8).

pub mod adapters;
mod netlink;
