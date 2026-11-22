use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{broadcast, watch};

use super::UsbDevice;

/// Current reported devices, keyed by USB port.
pub type UsbSnapshot = BTreeMap<String, Arc<UsbDevice>>;

/// A change to the USB inventory.
#[derive(Debug, Clone)]
pub enum UsbEvent {
    /// A device finished enumerating.
    Attached(Arc<UsbDevice>),
    /// A device's record changed.
    Changed(Arc<UsbDevice>),
    /// A known device was removed.
    Detached(Arc<UsbDevice>),
}

/// Subscribers can retain this handle through a module restart.
#[derive(Debug, Clone)]
pub struct UsbHandle {
    pub(super) events: broadcast::Sender<UsbEvent>,
    pub(super) devices: watch::Sender<Arc<UsbSnapshot>>,
    pub(super) initialized: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for UsbHandle {
    fn default() -> Self {
        let (events, _) = broadcast::channel(64);
        let (devices, _) = watch::channel(Arc::default());
        Self {
            events,
            devices,
            initialized: Arc::default(),
        }
    }
}

impl UsbHandle {
    /// Subscribe to future inventory changes. Read the snapshot again after lagging.
    pub fn subscribe(&self) -> broadcast::Receiver<UsbEvent> {
        self.events.subscribe()
    }

    /// For other modules' tests (so far the stream module's): replaces the snapshot as if the
    /// usb module had scanned.
    #[cfg(all(test, feature = "module-stream"))]
    pub(crate) fn set_for_test(&self, devices: UsbSnapshot) {
        self.devices.send_replace(Arc::new(devices));
    }

    /// Watch the current inventory, including devices present at startup.
    pub fn snapshot(&self) -> watch::Receiver<Arc<UsbSnapshot>> {
        self.devices.subscribe()
    }
}
