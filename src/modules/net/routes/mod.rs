//! Source-based routing for bonded uplinks (LLD 3, section 5): `helios net routes`, which
//! `helios-routes.service` runs with only `CAP_NET_ADMIN`.
//!
//! srtla_send binds one socket per uplink address, but without a rule the kernel routes all of
//! them by the main table, so every link leaves through the lowest-metric interface (found on the
//! Orange Pi, 2026-11-22). For each interface with an IPv4 address and a main-table default route
//! (except excluded and virtual ones), this keeps table `10000 + ifindex` holding its default and
//! subnet routes and a rule `from <address> lookup <table>`, following address and route changes.
//! Traffic that doesn't bind an address still uses the main table. It never writes the main table,
//! and at stop removes everything it added.

pub(crate) mod kernel;
pub(crate) mod plan;

use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use super::NetSettings;
use super::netlink::{Kernel, Rtnetlink};
use kernel::RouteKernel;
use plan::{Change, Uplink};

/// How long the tables must be quiet after a change before routing is reconciled.
const QUIET: Duration = Duration::from_secs(1);
/// The longest a change waits while changes keep coming.
const MAX_DELAY: Duration = Duration::from_secs(5);
/// How often routing is reconciled anyway.
const RESYNC: Duration = Duration::from_secs(60);

/// What one reconcile found and did.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) uplinks: Vec<Uplink>,
    pub(crate) applied: Vec<Change>,
    /// Changes the kernel refused, with why.
    pub(crate) failed: Vec<(Change, String)>,
}

/// Which interfaces get no source routing: the excluded and the virtual ones (no device in sysfs,
/// such as WireGuard, Docker bridges and tunnels).
pub(crate) fn skipper<'a>(
    settings: &'a NetSettings,
    sysfs: &'a Path,
) -> impl Fn(&str) -> bool + 'a {
    move |name: &str| {
        settings.excludes(name) || !sysfs.join("class/net").join(name).join("device").exists()
    }
}

/// Reads the network, works out the wanted rules and routes, and applies the difference.
///
/// # Errors
///
/// When the network or Helios's current rules and routes can't be read. A refused change is
/// recorded in [`Outcome::failed`] and the rest still applied.
pub(crate) fn reconcile(
    kernel: &dyn Kernel,
    routes: &dyn RouteKernel,
    skip: &dyn Fn(&str) -> bool,
) -> io::Result<Outcome> {
    let tables = super::netlink::read(kernel)?;
    let uplinks = plan::uplinks(&tables, skip);
    let wanted = plan::wanted(&uplinks);
    let current = routes.current()?;
    let mut outcome = Outcome {
        uplinks,
        ..Outcome::default()
    };
    for change in plan::changes(&current, &wanted) {
        match routes.apply(&change) {
            Ok(()) => outcome.applied.push(change),
            Err(error) => outcome.failed.push((change, error.to_string())),
        }
    }
    Ok(outcome)
}

/// Removes every rule and route Helios added.
///
/// # Errors
///
/// When Helios's rules and routes can't be read; refused deletions are in the outcome.
pub(crate) fn remove(routes: &dyn RouteKernel) -> io::Result<Outcome> {
    let current = routes.current()?;
    let mut outcome = Outcome::default();
    for change in plan::changes(&current, &plan::State::default()) {
        match routes.apply(&change) {
            Ok(()) => outcome.applied.push(change),
            Err(error) => outcome.failed.push((change, error.to_string())),
        }
    }
    Ok(outcome)
}

/// Logs what a reconcile did.
fn log(outcome: &Outcome) {
    for (change, error) in &outcome.failed {
        tracing::warn!(?change, %error, "the kernel refused a source-routing change");
    }
    if !outcome.applied.is_empty() {
        let uplinks: Vec<String> = outcome
            .uplinks
            .iter()
            .map(|uplink| format!("{} (table {})", uplink.name, uplink.table()))
            .collect();
        tracing::info!(
            changes = outcome.applied.len(),
            uplinks = uplinks.join(", "),
            "source routing updated"
        );
    }
}

/// The rp_filter settings (LLD 3, section 5.7: tested to pass with the per-uplink rules under
/// every mode, so only logged).
fn log_rp_filter(uplinks: &[Uplink]) {
    let read = |name: &str| {
        std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))
            .map(|text| text.trim().to_owned())
            .unwrap_or_else(|_| "?".into())
    };
    let settings: Vec<String> = std::iter::once("all".to_owned())
        .chain(uplinks.iter().map(|u| u.name.clone()))
        .map(|name| format!("{name}={}", read(&name)))
        .collect();
    tracing::info!(rp_filter = settings.join(" "), "reverse-path filtering");
}

/// `helios net routes`: reconciles until SIGTERM or SIGINT, then removes everything it added.
///
/// # Errors
///
/// When the network can't be read or watched.
pub(crate) fn run(settings: &NetSettings, sysfs: &Path) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(watch(settings, sysfs))
}

async fn watch(settings: &NetSettings, sysfs: &Path) -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut watch = Rtnetlink.watch()?;
    let (changed, mut changes) = mpsc::channel(1);
    std::thread::Builder::new()
        .name("helios-routes".into())
        .spawn(move || {
            loop {
                match watch.wait() {
                    Ok(true) => {
                        if changed.blocking_send(()).is_err() {
                            return;
                        }
                    }
                    Ok(false) => {
                        if changed.is_closed() {
                            return;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, "can't read network changes");
                        return;
                    }
                }
            }
        })?;
    let skip = skipper(settings, sysfs);
    let first = reconcile(&Rtnetlink, &kernel::Netlink, &skip)?;
    log(&first);
    log_rp_filter(&first.uplinks);
    let mut first_change: Option<Instant> = None;
    let mut quiet_until = Instant::now();
    let mut resync_at = Instant::now() + RESYNC;
    loop {
        let due = first_change.map(|first| quiet_until.min(first + MAX_DELAY));
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            change = changes.recv() => {
                if change.is_none() {
                    break;
                }
                let now = Instant::now();
                first_change.get_or_insert(now);
                quiet_until = now + QUIET;
            }
            () = sleep_until(due) => {
                first_change = None;
                reconcile_logged(&skip);
                resync_at = Instant::now() + RESYNC;
            }
            () = tokio::time::sleep_until(resync_at) => {
                reconcile_logged(&skip);
                resync_at = Instant::now() + RESYNC;
            }
        }
    }
    let removed = remove(&kernel::Netlink)?;
    tracing::info!(removed = removed.applied.len(), "source routing removed");
    Ok(())
}

fn reconcile_logged(skip: &dyn Fn(&str) -> bool) {
    match reconcile(&Rtnetlink, &kernel::Netlink, skip) {
        Ok(outcome) => log(&outcome),
        Err(error) => tracing::warn!(%error, "can't reconcile source routing"),
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// `[modules.net]` from the config file, for its `exclude`; the defaults when there's none.
///
/// # Errors
///
/// When the file can't be read or `[modules.net]` doesn't parse.
pub(crate) fn settings(config: &Path) -> Result<NetSettings, String> {
    let text = std::fs::read_to_string(config)
        .map_err(|error| format!("{}: {error}", config.display()))?;
    let table: toml::Table =
        toml::from_str(&text).map_err(|error| format!("{}: {error}", config.display()))?;
    match table.get("modules").and_then(|m| m.get("net")) {
        Some(net) => net
            .clone()
            .try_into::<NetSettings>()
            .map_err(|error| format!("{}: [modules.net]: {error}", config.display())),
        None => Ok(NetSettings::default()),
    }
}

#[cfg(test)]
mod tests;
