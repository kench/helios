//! `helios usb`: the USB devices present, and the kernel's USB-related events (LLD 5), for
//! checking devices on hardware and recording test fixtures.

use std::io::{self, Write};
use std::path::Path;

use crate::modules::usb::sysfs::Inventory;
use crate::modules::usb::uevent::{Socket, Uevent, UeventSource, parse};

#[derive(Debug, clap::Subcommand)]
pub(super) enum Command {
    /// List devices currently present.
    List,
    /// Watch USB-related kernel events.
    Monitor {
        ///Print raw NUL-separated messages as JSON strings for replay.
        #[arg(long)]
        raw: bool,
    },
}

pub(super) fn run(command: Command, output: &mut dyn Write) -> Result<(), super::Failure> {
    match command {
        Command::List => {
            let inventory = Inventory {
                sysfs: Path::new("/sys"),
                labels: Path::new("/dev/disk/by-label"),
                mountinfo: Path::new("/proc/self/mountinfo"),
                mp_sd: Path::new("/init/efad/mp_sd"),
            };
            list(&inventory, output)?;
            Ok(())
        }
        Command::Monitor { raw } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(monitor(raw, output))?;
            Ok(())
        }
    }
}

/// Writes every device `inventory` finds, as the module's records, in JSON.
fn list(inventory: &Inventory<'_>, output: &mut dyn Write) -> io::Result<()> {
    let records: Vec<_> = inventory
        .scan()
        .into_iter()
        .map(|device| device.payload)
        .collect();
    serde_json::to_writer_pretty(&mut *output, &records).map_err(io::Error::from)?;
    writeln!(output)
}

/// Whether the monitor shows `event`: the module's subsystems, below a USB device.
fn relevant(event: &Uevent) -> bool {
    ["usb", "net", "video4linux", "sound", "tty", "block"].contains(&event.subsystem.as_str())
        && event.path.split('/').any(crate::modules::usb::is_port)
}

async fn monitor(raw: bool, output: &mut dyn Write) -> io::Result<()> {
    let mut socket = Socket::open()?;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        let message = tokio::select! {
            result = &mut shutdown => return result,
            message = socket.receive() => message?,
        };
        let Some(event) = parse(&message.bytes, message.sender) else {
            continue;
        };
        if !relevant(&event) {
            continue;
        }
        if raw {
            serde_json::to_writer(&mut *output, &String::from_utf8_lossy(&message.bytes))?;
            writeln!(output)?;
        } else {
            writeln!(
                output,
                "{} {} {}",
                event.action, event.subsystem, event.path
            )?;
        }
        output.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(subsystem: &str, path: &str) -> Uevent {
        parse(
            format!("add@{path}\0ACTION=add\0DEVPATH={path}\0SUBSYSTEM={subsystem}\0").as_bytes(),
            0,
        )
        .expect("event")
    }

    #[test]
    fn monitors_only_usb_related_events() {
        assert!(relevant(&event("usb", "/devices/platform/usb1/1-2")));
        assert!(relevant(&event(
            "net",
            "/devices/platform/usb1/1-2/1-2:1.0/net/eth1"
        )));
        assert!(!relevant(&event(
            "net",
            "/devices/platform/ethernet/net/eth0"
        )));
        assert!(!relevant(&event(
            "input",
            "/devices/platform/usb1/1-2/input/input3"
        )));
    }

    #[test]
    fn lists_devices_as_json() {
        let root = tempfile::tempdir().expect("fixture");
        let device = root.path().join("devices/platform/usb1/1-2");
        std::fs::create_dir_all(&device).expect("device");
        std::fs::write(device.join("idVendor"), "091e").expect("vendor");
        std::fs::write(device.join("idProduct"), "0003").expect("product");
        std::fs::create_dir_all(root.path().join("bus/usb/devices")).expect("bus");
        std::os::unix::fs::symlink(&device, root.path().join("bus/usb/devices/1-2")).expect("link");
        let labels = root.path().join("labels");
        let mountinfo = root.path().join("mountinfo");
        let inventory = Inventory {
            sysfs: root.path(),
            labels: &labels,
            mountinfo: &mountinfo,
            mp_sd: Path::new("/init/efad/mp_sd"),
        };
        let mut output = Vec::new();

        list(&inventory, &mut output).expect("listed");

        let records: serde_json::Value = serde_json::from_slice(&output).expect("JSON");
        assert_eq!(records[0]["port"], "1-2");
        assert_eq!(records[0]["vid"], "091e");
        assert_eq!(records[0]["pid"], "0003");
    }
}
