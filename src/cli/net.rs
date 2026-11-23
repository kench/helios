//! `helios net`: the network interfaces, their addresses and default routes, as the net module
//! would report them (LLD 3), for checking a device's networking on hardware.

use std::io::{self, Write};
use std::path::Path;

use serde_json::json;

use crate::modules::net::netlink::{Kernel, Rtnetlink};
use crate::modules::net::nl80211::{Nl80211, Wireless};
use crate::modules::net::{NetSettings, current};

#[derive(Debug, clap::Subcommand)]
pub(super) enum Command {
    /// List interfaces, their link state, addresses and default routes, as JSON. Uses the
    /// default settings (veth* left out), and has no `since`: only the module tracks that.
    List,
    /// Keep source routing for bonded uplinks (LLD 3, section 5): a table and a rule per
    /// interface with an IPv4 default route, so traffic from each address leaves through its own
    /// interface. helios-routes.service runs this with CAP_NET_ADMIN; it removes what it added
    /// when it stops.
    Routes {
        /// Reconcile once and exit (print what changed), instead of following changes.
        #[arg(long, conflicts_with = "remove")]
        once: bool,
        /// Remove every rule and route this added, and exit.
        #[arg(long)]
        remove: bool,
        /// Where to look for interfaces' devices (virtual interfaces have none).
        #[arg(long, default_value = "/sys", hide = true)]
        sysfs: std::path::PathBuf,
    },
}

pub(super) fn run(
    command: Command,
    config: &Path,
    output: &mut dyn Write,
) -> Result<(), super::Failure> {
    use crate::modules::net::routes;
    match command {
        Command::List => {
            list(&Rtnetlink, &Nl80211, Path::new("/sys"), output)?;
            Ok(())
        }
        Command::Routes {
            once,
            remove,
            sysfs,
        } => {
            let settings = routes::settings(config).map_err(super::Failure::config)?;
            if remove {
                let outcome = routes::remove(&routes::kernel::Netlink)?;
                writeln!(output, "removed {} rules and routes", outcome.applied.len())?;
                return refused(&outcome);
            }
            if once {
                let skip = routes::skipper(&settings, &sysfs);
                let outcome = routes::reconcile(&Rtnetlink, &routes::kernel::Netlink, &skip)?;
                for uplink in &outcome.uplinks {
                    writeln!(output, "{} table {}", uplink.name, uplink.table())?;
                }
                writeln!(output, "{} changes", outcome.applied.len())?;
                return refused(&outcome);
            }
            routes::run(&settings, &sysfs)?;
            Ok(())
        }
    }
}

/// A reconcile's refused changes as a failure (EPERM: run with CAP_NET_ADMIN).
fn refused(outcome: &crate::modules::net::routes::Outcome) -> Result<(), super::Failure> {
    match outcome.failed.first() {
        None => Ok(()),
        Some((change, error)) => Err(super::Failure::error(format!(
            "{} changes refused, the first {change:?}: {error}",
            outcome.failed.len()
        ))),
    }
}

/// Writes the snapshot of `kernel`'s interfaces, in JSON.
fn list(
    kernel: &dyn Kernel,
    wireless: &dyn Wireless,
    sysfs: &Path,
    output: &mut dyn Write,
) -> io::Result<()> {
    let snapshot = current(kernel, wireless, sysfs, &NetSettings::default())?;
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
        list(&Rtnetlink, &Nl80211, Path::new("/sys"), &mut output).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let interfaces = document["interfaces"].as_object().unwrap();
        assert!(!interfaces.contains_key("lo"), "loopback is left out");
        assert_eq!(document["truncated"].as_bool(), Some(false));
    }

    #[test]
    fn the_command_writes_the_list() {
        let mut output = Vec::new();
        run(Command::List, Path::new("/nonexistent"), &mut output).unwrap();
        assert!(output.ends_with(b"}\n"));
    }
}
