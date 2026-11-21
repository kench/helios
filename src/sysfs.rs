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

#[cfg(feature = "module-usb")]
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
