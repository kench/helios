//! Bootstrap: the token PIN and device identity from the bootstrap service, looked up by the
//! permanent MAC addresses of the device's built-in network adapters (LLD 1, section 4.8).

use std::path::Path;

pub mod adapters;
pub mod api;
pub mod challenge;
pub mod client;
mod netlink;

/// Where the board's model name is on devices with a device tree.
pub const DEVICE_TREE_MODEL: &str = "/proc/device-tree/model";

/// The longest `hardwareModel` the API accepts.
const MAX_HARDWARE_MODEL_LEN: usize = 128;

/// The hardware model from `path` (normally [`DEVICE_TREE_MODEL`]), such as `Raspberry Pi 5
/// Model B Rev 1.0`, for the bootstrap request. `None` if there isn't one. The device tree
/// stores it NUL-terminated.
#[must_use]
pub fn hardware_model(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let model = text.trim_end_matches('\0').trim();
    if model.is_empty() {
        return None;
    }
    Some(model.chars().take(MAX_HARDWARE_MODEL_LEN).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_device_tree_model() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("model");

        std::fs::write(&path, b"Raspberry Pi 5 Model B Rev 1.0\0").unwrap();
        assert_eq!(
            hardware_model(&path).as_deref(),
            Some("Raspberry Pi 5 Model B Rev 1.0")
        );
        std::fs::write(&path, "x".repeat(200)).unwrap();
        assert_eq!(hardware_model(&path).unwrap().len(), 128);
        std::fs::write(&path, b"\0").unwrap();
        assert_eq!(hardware_model(&path), None);
        assert_eq!(hardware_model(&directory.path().join("missing")), None);
    }
}
