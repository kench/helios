//! `helios net`: the network interfaces, their addresses and default routes, as the net module
//! would report them (LLD 3), for checking a device's networking on hardware.

use std::io::{self, Write};
use std::path::Path;

use serde_json::json;

use crate::modules::net::netlink::{Kernel, Rtnetlink};
use crate::modules::net::{NetSettings, current};

#[derive(Debug, clap::Subcommand)]
pub(super) enum Command {
    /// List interfaces, their link state, addresses and default routes, as JSON. Uses the
    /// default settings (veth* left out), and has no `since`: only the module tracks that.
    List,
}

pub(super) fn run(command: Command, output: &mut dyn Write) -> Result<(), super::Failure> {
    match command {
        Command::List => {
            list(&Rtnetlink, Path::new("/sys"), output)?;
            Ok(())
        }
    }
}

/// Writes the snapshot of `kernel`'s interfaces, in JSON.
fn list(kernel: &dyn Kernel, sysfs: &Path, output: &mut dyn Write) -> io::Result<()> {
    let snapshot = current(kernel, sysfs, &NetSettings::default())?;
    let document = json!({
        "interfaces": snapshot.interfaces,
        "truncated": snapshot.truncated,
    });
    serde_json::to_writer_pretty(&mut *output, &document).map_err(io::Error::from)?;
    writeln!(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_this_machines_interfaces_as_json() {
        let mut output = Vec::new();
        list(&Rtnetlink, Path::new("/sys"), &mut output).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let interfaces = document["interfaces"].as_object().unwrap();
        assert!(!interfaces.contains_key("lo"), "loopback is left out");
        assert_eq!(document["truncated"].as_bool(), Some(false));
    }

    #[test]
    fn the_command_writes_the_list() {
        let mut output = Vec::new();
        run(Command::List, &mut output).unwrap();
        assert!(output.ends_with(b"}\n"));
    }
}
