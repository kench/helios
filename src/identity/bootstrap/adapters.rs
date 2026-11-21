//! Finds the device's built-in network adapters and their permanent MAC addresses (LLD 1,
//! section 4.8).
//!
//! With `bootstrap.interfaces = "auto"`, an adapter is built in if it is an Ethernet-type
//! interface (`ARPHRD_ETHER`, which includes Wi-Fi) with a physical device that isn't attached
//! through USB. That leaves out USB Ethernet adapters, cellular modems and virtual interfaces.
//!
//! The MAC must be permanent: `IFLA_PERM_ADDRESS` over rtnetlink, or the current address only
//! if sysfs says it was assigned permanently (`addr_assign_type` 0). A randomized address
//! (NetworkManager Wi-Fi MAC randomization, or a board that makes one up at boot) wouldn't
//! match the bootstrap service's records.

use crate::sysfs::on_usb;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Serialize, Serializer};

/// The bootstrap API accepts at most this many adapters.
pub const MAX_ADAPTERS: usize = 8;

/// `ARPHRD_ETHER` in `/sys/class/net/<if>/type`.
const ARPHRD_ETHER: &str = "1";
/// `NET_ADDR_PERM` in `/sys/class/net/<if>/addr_assign_type`.
const NET_ADDR_PERM: &str = "0";

/// A MAC address, shown lowercase and colon-separated.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// The address with these bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// The address bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 6] {
        self.0
    }

    pub(crate) fn is_zero(self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl Serialize for MacAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({self})")
    }
}

/// The text isn't a colon-separated MAC address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a MAC address")]
pub struct ParseMacError(String);

impl FromStr for MacAddress {
    type Err = ParseMacError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let error = || ParseMacError(text.to_owned());
        let mut bytes = [0u8; 6];
        let mut parts = text.split(':');
        for byte in &mut bytes {
            let part = parts.next().ok_or_else(error)?;
            if part.len() != 2 {
                return Err(error());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| error())?;
        }
        if parts.next().is_some() {
            return Err(error());
        }
        Ok(Self(bytes))
    }
}

/// What kind of adapter it is, as the bootstrap API names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterKind {
    /// Wired Ethernet.
    Ethernet,
    /// Wi-Fi.
    Wifi,
}

impl AdapterKind {
    /// The name used in the bootstrap API.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Wifi => "wifi",
        }
    }
}

/// A built-in network adapter with its permanent MAC address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Adapter {
    /// The interface name, such as `eth0`.
    pub interface_name: String,
    /// Ethernet or Wi-Fi.
    pub kind: AdapterKind,
    /// The permanent MAC address.
    pub mac: MacAddress,
}

/// Which interfaces to use (`bootstrap.interfaces`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interfaces {
    /// Find the built-in adapters.
    Auto,
    /// Exactly these interfaces, for platforms where auto-detection picks the wrong ones.
    Named(Vec<String>),
}

/// Why the adapters couldn't be found. All of these are configuration problems, so they are
/// fatal (exit 78).
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// No built-in adapter with a permanent MAC address was found.
    #[error(
        "no built-in network adapter with a permanent MAC address found; set \
         bootstrap.interfaces explicitly"
    )]
    NoBuiltInAdapter,
    /// A configured interface doesn't exist.
    #[error("network interface {0:?} does not exist")]
    NotFound(String),
    /// A configured interface has no permanent MAC address.
    #[error("network interface {0:?} has no permanent MAC address")]
    NoPermanentAddress(String),
    /// sysfs couldn't be read.
    #[error("{path}: {source}")]
    Io {
        /// The path that couldn't be read.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
}

/// Where permanent MAC addresses come from. The real one asks the kernel over rtnetlink.
pub trait PermanentAddresses: Send + Sync {
    /// `interface`'s permanent MAC, or `None` if the kernel or driver doesn't report one.
    ///
    /// # Errors
    ///
    /// Any error asking for it. The sysfs fallback is used then.
    fn permanent_address(&self, interface: &str) -> io::Result<Option<MacAddress>>;
}

/// Permanent addresses from rtnetlink (`IFLA_PERM_ADDRESS`, Linux 5.6 and later).
#[derive(Debug, Clone, Copy, Default)]
pub struct Rtnetlink;

impl PermanentAddresses for Rtnetlink {
    fn permanent_address(&self, interface: &str) -> io::Result<Option<MacAddress>> {
        super::netlink::permanent_address(interface)
    }
}

/// Finds the adapters to send to the bootstrap service, sorted by interface name.
///
/// `sysfs` is normally `/sys`.
///
/// # Errors
///
/// [`AdapterError::NoBuiltInAdapter`] if none is found, [`AdapterError::NotFound`] or
/// [`AdapterError::NoPermanentAddress`] for a configured interface, and [`AdapterError::Io`]
/// if sysfs can't be read.
pub fn find_adapters(
    sysfs: &Path,
    interfaces: &Interfaces,
    permanent: &dyn PermanentAddresses,
) -> Result<Vec<Adapter>, AdapterError> {
    let net = sysfs.join("class/net");
    let mut adapters = Vec::new();
    match interfaces {
        Interfaces::Auto => {
            let entries = std::fs::read_dir(&net).map_err(|source| AdapterError::Io {
                path: net.clone(),
                source,
            })?;
            let mut names: Vec<String> = entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect();
            names.sort();
            for name in names {
                let interface = net.join(&name);
                if !is_built_in(&interface) {
                    continue;
                }
                match permanent_mac(&name, &interface, permanent) {
                    Some(mac) => adapters.push(adapter(name, &interface, mac)),
                    None => tracing::warn!(
                        interface = %name,
                        "built-in adapter has no permanent MAC address; leaving it out"
                    ),
                }
            }
        }
        Interfaces::Named(names) => {
            let mut names = names.clone();
            names.sort();
            names.dedup();
            for name in names {
                let interface = net.join(&name);
                if name.contains('/') || !interface.exists() {
                    return Err(AdapterError::NotFound(name));
                }
                let mac = permanent_mac(&name, &interface, permanent)
                    .ok_or_else(|| AdapterError::NoPermanentAddress(name.clone()))?;
                adapters.push(adapter(name, &interface, mac));
            }
        }
    }
    if adapters.is_empty() {
        return Err(AdapterError::NoBuiltInAdapter);
    }
    if adapters.len() > MAX_ADAPTERS {
        tracing::warn!(
            count = adapters.len(),
            "more built-in adapters than the bootstrap API accepts; using the first {MAX_ADAPTERS}"
        );
        adapters.truncate(MAX_ADAPTERS);
    }
    Ok(adapters)
}

fn adapter(interface_name: String, interface: &Path, mac: MacAddress) -> Adapter {
    let wifi = interface.join("wireless").exists() || interface.join("phy80211").exists();
    Adapter {
        interface_name,
        kind: if wifi {
            AdapterKind::Wifi
        } else {
            AdapterKind::Ethernet
        },
        mac,
    }
}

/// An Ethernet-type interface with a physical device that isn't on USB.
fn is_built_in(interface: &Path) -> bool {
    if read_trimmed(&interface.join("type")).as_deref() != Some(ARPHRD_ETHER) {
        return false;
    }
    let Ok(device) = std::fs::canonicalize(interface.join("device")) else {
        // Virtual interfaces (bridges, VPNs, veth pairs) have no device.
        return false;
    };
    !on_usb(&device)
}

/// The permanent MAC: from the kernel if it reports one, otherwise the current address if it
/// was assigned permanently.
fn permanent_mac(
    name: &str,
    interface: &Path,
    permanent: &dyn PermanentAddresses,
) -> Option<MacAddress> {
    match permanent.permanent_address(name) {
        Ok(Some(mac)) => return Some(mac),
        Ok(None) => {}
        Err(error) => tracing::debug!(
            interface = %name,
            %error,
            "IFLA_PERM_ADDRESS unavailable; using sysfs"
        ),
    }
    if read_trimmed(&interface.join("addr_assign_type")).as_deref() != Some(NET_ADDR_PERM) {
        return None;
    }
    read_trimmed(&interface.join("address"))?
        .parse::<MacAddress>()
        .ok()
        .filter(|mac| !mac.is_zero())
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::symlink;

    use super::*;

    /// A fake `/sys` with interfaces linked from `class/net` into `devices`, as on Linux.
    struct Sysfs {
        root: tempfile::TempDir,
    }

    #[derive(Clone, Copy)]
    struct Interface<'a> {
        name: &'a str,
        /// Where the interface sits under `devices`. `None` for virtual interfaces.
        device_path: Option<&'a str>,
        type_: &'a str,
        address: &'a str,
        addr_assign_type: Option<&'a str>,
        wireless: bool,
    }

    impl<'a> Interface<'a> {
        fn ethernet(name: &'a str, device_path: &'a str, address: &'a str) -> Self {
            Self {
                name,
                device_path: Some(device_path),
                type_: "1",
                address,
                addr_assign_type: Some("0"),
                wireless: false,
            }
        }
    }

    impl Sysfs {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("class/net")).unwrap();
            Self { root }
        }

        fn path(&self) -> &Path {
            self.root.path()
        }

        fn add(&self, interface: Interface<'_>) -> &Self {
            let root = self.root.path();
            let directory = match interface.device_path {
                Some(device) => {
                    let device = root.join("devices").join(device);
                    std::fs::create_dir_all(&device).unwrap();
                    let directory = device.join("net").join(interface.name);
                    std::fs::create_dir_all(&directory).unwrap();
                    symlink(&device, directory.join("device")).unwrap();
                    directory
                }
                None => {
                    let directory = root.join("devices/virtual/net").join(interface.name);
                    std::fs::create_dir_all(&directory).unwrap();
                    directory
                }
            };
            std::fs::write(directory.join("type"), format!("{}\n", interface.type_)).unwrap();
            std::fs::write(
                directory.join("address"),
                format!("{}\n", interface.address),
            )
            .unwrap();
            if let Some(kind) = interface.addr_assign_type {
                std::fs::write(directory.join("addr_assign_type"), format!("{kind}\n")).unwrap();
            }
            if interface.wireless {
                std::fs::create_dir(directory.join("wireless")).unwrap();
            }
            symlink(&directory, root.join("class/net").join(interface.name)).unwrap();
            self
        }
    }

    /// Permanent addresses a test chooses. Interfaces it doesn't list have none.
    #[derive(Default)]
    struct Kernel(HashMap<String, io::Result<Option<MacAddress>>>);

    impl Kernel {
        fn with(mut self, interface: &str, result: io::Result<Option<MacAddress>>) -> Self {
            self.0.insert(interface.to_owned(), result);
            self
        }
    }

    impl PermanentAddresses for Kernel {
        fn permanent_address(&self, interface: &str) -> io::Result<Option<MacAddress>> {
            match self.0.get(interface) {
                Some(Ok(mac)) => Ok(*mac),
                Some(Err(error)) => Err(io::Error::new(error.kind(), error.to_string())),
                None => Ok(None),
            }
        }
    }

    fn mac(text: &str) -> MacAddress {
        text.parse().unwrap()
    }

    /// The Raspberry Pi 5: onboard Ethernet and Wi-Fi, plus a USB Ethernet adapter, a bridge,
    /// a WireGuard tunnel and loopback.
    fn raspberry_pi_5() -> Sysfs {
        let sysfs = Sysfs::new();
        sysfs
            .add(Interface::ethernet(
                "eth0",
                "platform/axi/1000120000.pcie/1f00100000.ethernet",
                "2c:cf:67:00:00:01",
            ))
            .add(Interface {
                wireless: true,
                ..Interface::ethernet(
                    "wlan0",
                    "platform/axi/1000110000.mmc/mmc_host/mmc1/mmc1:0001/mmc1:0001:1",
                    "2c:cf:67:00:00:02",
                )
            })
            .add(Interface::ethernet(
                "eth1",
                "platform/axi/1000120000.pcie/1f00200000.usb/xhci-hcd.0/usb1/1-1/1-1:1.0",
                "00:e0:4c:00:00:03",
            ))
            .add(Interface {
                device_path: None,
                ..Interface::ethernet("br0", "", "2c:cf:67:00:00:01")
            })
            .add(Interface {
                device_path: None,
                type_: "65534",
                ..Interface::ethernet("wg0", "", "00:00:00:00:00:00")
            })
            .add(Interface {
                device_path: None,
                type_: "772",
                ..Interface::ethernet("lo", "", "00:00:00:00:00:00")
            });
        sysfs
    }

    #[test]
    fn finds_the_built_in_ethernet_and_wifi_adapters() {
        let sysfs = raspberry_pi_5();

        let adapters = find_adapters(sysfs.path(), &Interfaces::Auto, &Kernel::default()).unwrap();

        assert_eq!(
            adapters,
            [
                Adapter {
                    interface_name: "eth0".into(),
                    kind: AdapterKind::Ethernet,
                    mac: mac("2c:cf:67:00:00:01"),
                },
                Adapter {
                    interface_name: "wlan0".into(),
                    kind: AdapterKind::Wifi,
                    mac: mac("2c:cf:67:00:00:02"),
                },
            ]
        );
    }

    #[test]
    fn prefers_the_permanent_address_from_the_kernel() {
        let sysfs = Sysfs::new();
        // NetworkManager randomized the Wi-Fi address.
        sysfs.add(Interface {
            wireless: true,
            addr_assign_type: Some("3"),
            ..Interface::ethernet("wlan0", "platform/mmc1:0001:1", "f6:12:34:56:78:9a")
        });
        let kernel = Kernel::default().with("wlan0", Ok(Some(mac("2c:cf:67:00:00:02"))));

        let adapters = find_adapters(sysfs.path(), &Interfaces::Auto, &kernel).unwrap();

        assert_eq!(adapters[0].mac, mac("2c:cf:67:00:00:02"));
    }

    #[test]
    fn leaves_out_randomized_addresses_without_a_permanent_one() {
        for assign_type in [Some("1"), Some("2"), Some("3"), None] {
            let sysfs = Sysfs::new();
            sysfs
                .add(Interface::ethernet(
                    "eth0",
                    "platform/eth",
                    "00:11:22:33:44:55",
                ))
                .add(Interface {
                    wireless: true,
                    addr_assign_type: assign_type,
                    ..Interface::ethernet("wlan0", "platform/mmc", "f6:12:34:56:78:9a")
                });

            let adapters =
                find_adapters(sysfs.path(), &Interfaces::Auto, &Kernel::default()).unwrap();

            assert_eq!(adapters.len(), 1, "{assign_type:?}");
            assert_eq!(adapters[0].interface_name, "eth0");
        }
    }

    #[test]
    fn falls_back_to_sysfs_when_the_kernel_cannot_say() {
        // The scanner runs Linux 4.9, which has no IFLA_PERM_ADDRESS.
        let sysfs = Sysfs::new();
        sysfs.add(Interface::ethernet(
            "eth0",
            "soc0/soc/2100000.aips-bus/2188000.ethernet",
            "00:11:22:33:44:55",
        ));
        let kernel = Kernel::default().with(
            "eth0",
            Err(io::Error::new(io::ErrorKind::Unsupported, "old kernel")),
        );

        let adapters = find_adapters(sysfs.path(), &Interfaces::Auto, &kernel).unwrap();

        assert_eq!(adapters[0].mac, mac("00:11:22:33:44:55"));
    }

    #[test]
    fn needs_at_least_one_built_in_adapter() {
        let sysfs = Sysfs::new();
        sysfs
            .add(Interface::ethernet(
                "eth1",
                "pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0",
                "00:e0:4c:00:00:03",
            ))
            .add(Interface {
                addr_assign_type: Some("1"),
                ..Interface::ethernet("eth0", "platform/eth", "00:00:00:00:00:00")
            });

        let error = find_adapters(sysfs.path(), &Interfaces::Auto, &Kernel::default()).unwrap_err();

        assert!(matches!(error, AdapterError::NoBuiltInAdapter), "{error:?}");
        assert!(error.to_string().contains("set bootstrap.interfaces"));
    }

    #[test]
    fn a_zero_address_is_not_permanent() {
        let sysfs = Sysfs::new();
        sysfs.add(Interface::ethernet(
            "eth0",
            "platform/eth",
            "00:00:00:00:00:00",
        ));

        let error = find_adapters(sysfs.path(), &Interfaces::Auto, &Kernel::default()).unwrap_err();

        assert!(matches!(error, AdapterError::NoBuiltInAdapter));
    }

    #[test]
    fn named_interfaces_override_detection() {
        let sysfs = raspberry_pi_5();
        let interfaces = Interfaces::Named(vec!["wlan0".into(), "eth1".into(), "wlan0".into()]);

        let adapters = find_adapters(sysfs.path(), &interfaces, &Kernel::default()).unwrap();

        // The USB adapter is used because it was named. Sorted and without duplicates.
        let names: Vec<_> = adapters.iter().map(|a| a.interface_name.as_str()).collect();
        assert_eq!(names, ["eth1", "wlan0"]);
    }

    #[test]
    fn named_interfaces_must_exist_and_have_a_permanent_address() {
        let sysfs = raspberry_pi_5();

        for name in ["eth9", "../eth0"] {
            let error = find_adapters(
                sysfs.path(),
                &Interfaces::Named(vec![name.into()]),
                &Kernel::default(),
            )
            .unwrap_err();
            assert!(matches!(error, AdapterError::NotFound(_)), "{error:?}");
        }
        let error = find_adapters(
            sysfs.path(),
            &Interfaces::Named(vec!["wg0".into()]),
            &Kernel::default(),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "network interface \"wg0\" has no permanent MAC address"
        );
        let error = find_adapters(
            sysfs.path(),
            &Interfaces::Named(Vec::new()),
            &Kernel::default(),
        )
        .unwrap_err();
        assert!(matches!(error, AdapterError::NoBuiltInAdapter));
    }

    #[test]
    fn sends_at_most_eight_adapters() {
        let sysfs = Sysfs::new();
        let names: Vec<String> = (0..10).map(|i| format!("eth{i}")).collect();
        let addresses: Vec<String> = (0..10).map(|i| format!("00:11:22:33:44:{i:02x}")).collect();
        let devices: Vec<String> = (0..10).map(|i| format!("platform/eth{i}")).collect();
        for i in 0..10 {
            sysfs.add(Interface::ethernet(&names[i], &devices[i], &addresses[i]));
        }

        let adapters = find_adapters(sysfs.path(), &Interfaces::Auto, &Kernel::default()).unwrap();

        assert_eq!(adapters.len(), MAX_ADAPTERS);
        assert_eq!(adapters[0].interface_name, "eth0");
    }

    #[test]
    fn a_missing_sysfs_is_an_io_error() {
        let error = find_adapters(
            Path::new("/nonexistent/sys"),
            &Interfaces::Auto,
            &Kernel::default(),
        )
        .unwrap_err();

        assert!(matches!(error, AdapterError::Io { .. }), "{error:?}");
        assert!(
            error
                .to_string()
                .starts_with("/nonexistent/sys/class/net: ")
        );
    }

    #[test]
    fn mac_addresses_parse_and_print_lowercase() {
        let mac = mac("2C:cf:67:0A:00:01");

        assert_eq!(mac.to_string(), "2c:cf:67:0a:00:01");
        assert_eq!(mac.bytes(), [0x2c, 0xcf, 0x67, 0x0a, 0x00, 0x01]);
        assert_eq!(format!("{mac:?}"), "MacAddress(2c:cf:67:0a:00:01)");
        for bad in [
            "",
            "2c:cf:67:00:00",
            "2c:cf:67:00:00:01:02",
            "2c-cf-67-00-00-01",
            "2c:cf:67:00:00:1",
            "2c:cf:67:00:00:zz",
        ] {
            assert_eq!(
                bad.parse::<MacAddress>(),
                Err(ParseMacError(bad.into())),
                "{bad}"
            );
        }
        assert_eq!(
            ParseMacError("x".into()).to_string(),
            "\"x\" is not a MAC address"
        );
        assert_eq!(AdapterKind::Ethernet.as_str(), "ethernet");
        assert_eq!(AdapterKind::Wifi.as_str(), "wifi");
    }

    #[test]
    fn this_machine_has_an_answer() {
        // Smoke test against the real /sys and kernel: either some adapters or a clear error.
        match find_adapters(Path::new("/sys"), &Interfaces::Auto, &Rtnetlink) {
            Ok(adapters) => assert!(!adapters.is_empty()),
            Err(error) => assert!(matches!(error, AdapterError::NoBuiltInAdapter), "{error}"),
        }
    }
}
