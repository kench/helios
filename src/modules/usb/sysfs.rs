use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{Value, json};

use super::mounts;
use super::{UsbDevice, classify};
use crate::sysfs::{on_usb, read_attr};

pub(crate) struct Inventory<'a> {
    pub sysfs: &'a Path,
    pub labels: &'a Path,
    pub mountinfo: &'a Path,
    pub mp_sd: &'a Path,
}

pub(crate) fn entries(path: &Path) -> Vec<(String, PathBuf)> {
    let mut entries: Vec<_> = fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| Some((entry.file_name().into_string().ok()?, entry.path())))
        .collect();
    entries.sort();
    entries
}

fn attr(path: &Path, name: &str) -> Option<String> {
    read_attr(&path.join(name))
}

fn hex(path: &Path, name: &str) -> Option<u16> {
    u16::from_str_radix(&attr(path, name)?, 16).ok()
}

fn driver(path: &Path) -> Option<String> {
    Some(
        fs::read_link(path.join("driver"))
            .ok()?
            .file_name()?
            .to_str()?
            .into(),
    )
}

impl Inventory<'_> {
    pub(crate) fn scan(&self) -> Vec<UsbDevice> {
        let usb = entries(&self.sysfs.join("bus/usb/devices"));
        let mounts = mounts::parse(&fs::read_to_string(self.mountinfo).unwrap_or_default());
        let labels: Vec<_> = entries(self.labels)
            .into_iter()
            .filter_map(|(label, path)| {
                Some((
                    fs::read_link(path).ok()?.file_name()?.to_str()?.to_owned(),
                    label,
                ))
            })
            .collect();
        let classes: Vec<_> = ["net", "video4linux", "sound", "tty", "block"]
            .into_iter()
            .map(|class| (class, entries(&self.sysfs.join("class").join(class))))
            .collect();
        let mut devices = Vec::new();
        for (port, path) in &usb {
            if !super::is_port(port) {
                continue;
            }
            let Some((vid, pid)) = hex(path, "idVendor").zip(hex(path, "idProduct")) else {
                continue;
            };
            let Ok(real) = path.canonicalize() else {
                continue;
            };
            let prefix = format!("{port}:");
            let mut categories = BTreeSet::new();
            let mut interfaces = Vec::new();
            for (_, interface) in usb.iter().filter(|(name, _)| name.starts_with(&prefix)) {
                let class = hex(interface, "bInterfaceClass");
                let driver = driver(interface);
                categories.extend(classify::interface(class, driver.as_deref()));
                let format_hex =
                    |attribute| hex(interface, attribute).map(|value| format!("{value:02x}"));
                interfaces.push(json!({
                    "number": hex(interface, "bInterfaceNumber"), "class": format_hex("bInterfaceClass"),
                    "subclass": format_hex("bInterfaceSubClass"), "protocol": format_hex("bInterfaceProtocol"),
                    "driver": driver
                }));
            }
            let mut nodes = std::collections::BTreeMap::<&str, Vec<Value>>::from([
                ("net", Vec::new()),
                ("video", Vec::new()),
                ("alsa", Vec::new()),
                ("tty", Vec::new()),
                ("block", Vec::new()),
            ]);
            let mut mp_sd = false;
            for (class, members) in &classes {
                for (name, node) in members {
                    let Ok(node_path) = node.canonicalize() else {
                        continue;
                    };
                    let parent = node
                        .join("device")
                        .canonicalize()
                        .unwrap_or_else(|_| node_path.clone());
                    if !(on_usb(&parent) || on_usb(&node_path)) {
                        continue;
                    }
                    // A hub's children are separate USB devices, even though their paths
                    // start with the hub path.
                    if ![&parent, &node_path].into_iter().any(|candidate| {
                        candidate.strip_prefix(&real).ok().is_some_and(|suffix| {
                            suffix.components().next().is_none_or(|part| {
                                !part.as_os_str().to_str().is_some_and(super::is_port)
                            })
                        })
                    }) {
                        continue;
                    }
                    let (kind, data) = match *class {
                        "net" => {
                            let properties = attr(node, "uevent").unwrap_or_default();
                            let net_driver = driver(&parent);
                            categories.extend(classify::network(
                                node.join("phy80211").is_symlink()
                                    || node.join("wireless").is_dir(),
                                properties.lines().any(|line| line == "DEVTYPE=wwan"),
                                net_driver.as_deref(),
                                attr(node, "type").as_deref(),
                            ));
                            ("net", json!(name))
                        }
                        "video4linux" => {
                            categories.insert("video");
                            (
                                "video",
                                json!({"name": name, "index": attr(node, "index").and_then(|s| s.parse::<u32>().ok())}),
                            )
                        }
                        "sound" => {
                            let Some(number) = name
                                .strip_prefix("card")
                                .and_then(|s| s.parse::<u32>().ok())
                            else {
                                continue;
                            };
                            categories.insert("audio");
                            let prefix = format!("pcmC{number}D");
                            let has = |end| {
                                members.iter().any(|(name, _)| {
                                    name.starts_with(&prefix) && name.ends_with(end)
                                })
                            };
                            (
                                "alsa",
                                json!({"card": number, "id": attr(node, "id"), "capture": has('c'), "playback": has('p')}),
                            )
                        }
                        "tty" if name.starts_with("ttyUSB") || name.starts_with("ttyACM") => {
                            categories.insert("serial");
                            (
                                "tty",
                                json!({"name": name, "driver": parent.ancestors().take_while(|p| p.starts_with(&real)).find_map(driver)}),
                            )
                        }
                        "block" => {
                            categories.insert("storage");
                            let label = labels
                                .iter()
                                .find(|(target, _)| target == name)
                                .map(|(_, label)| label);
                            let device = attr(node, "dev");
                            let paths = device.as_ref().and_then(|dev| mounts.get(dev));
                            mp_sd |= label.is_some_and(|label| label == "MP_SD")
                                || paths.is_some_and(|paths| {
                                    paths.iter().any(|path| Path::new(path) == self.mp_sd)
                                });
                            let size = attr(node, "size")
                                .and_then(|s| s.parse::<u64>().ok())
                                .and_then(|size| size.checked_mul(512));
                            (
                                "block",
                                json!({"name": name, "size": size, "label": label, "mounts": paths.map_or(&[][..], Vec::as_slice)}),
                            )
                        }
                        _ => continue,
                    };
                    nodes.entry(kind).or_default().push(data);
                }
            }
            if categories.is_empty() {
                categories.insert("other");
            }
            let serial = attr(path, "serial");
            let key = serial
                .as_ref()
                .map(|serial| format!("{vid:04x}:{pid:04x}:{serial}"));
            let class = hex(path, "bDeviceClass");
            let payload = json!({
                "port": port, "devpath": port, "key": key, "vid": format!("{vid:04x}"),
                "pid": format!("{pid:04x}"), "manufacturer": attr(path, "manufacturer"),
                "product": attr(path, "product"), "serial": serial,
                "speed_mbps": attr(path, "speed").and_then(|s| s.parse::<f64>().ok()),
                "class": class, "interfaces": interfaces, "categories": categories, "nodes": nodes
            });
            let mut payload = payload.as_object().cloned().unwrap_or_default();
            if mp_sd {
                payload.insert("role".into(), json!("mp_sd"));
            }
            if !path.exists() {
                continue;
            }
            let devpath = self
                .sysfs
                .canonicalize()
                .ok()
                .and_then(|root| {
                    real.strip_prefix(root)
                        .ok()
                        .map(|path| format!("/{}", path.display()))
                })
                .unwrap_or_default();
            devices.push(UsbDevice {
                port: port.clone(),
                devpath,
                vid,
                pid,
                hub: class == Some(9),
                payload,
                attached_at: SystemTime::now(),
            });
        }
        devices
    }
}
