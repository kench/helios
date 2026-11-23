use std::path::Path;

/// Whether the sysfs device path is below a USB root hub.
pub(crate) fn on_usb(device: &Path) -> bool {
    device.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .and_then(|name| name.strip_prefix("usb"))
            .is_some_and(|bus| !bus.is_empty() && bus.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Whether `port` is a USB port name: `<bus>-<port>[.<port>…]` (`1-1.3`).
#[cfg(any(feature = "module-usb", feature = "module-net", feature = "module-gps"))]
pub(crate) fn is_port(port: &str) -> bool {
    let digits = |segment: &str| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit());
    port.split_once('-')
        .is_some_and(|(bus, chain)| digits(bus) && chain.split('.').all(digits))
}

/// The USB port a sysfs device path is below: its last component that names one.
#[cfg(any(feature = "module-net", feature = "module-gps"))]
pub(crate) fn usb_port(device: &Path) -> Option<String> {
    device
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .rfind(|name| is_port(name))
        .map(str::to_owned)
}

/// A sysfs attribute's text, trimmed (at most 256 bytes).
#[cfg(any(feature = "module-usb", feature = "module-net"))]
pub(crate) fn read_attr(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(256);
    std::fs::File::open(path)
        .ok()?
        .take(256)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).trim().to_owned())
}
