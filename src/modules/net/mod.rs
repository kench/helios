//! Network interfaces, their link state, addresses and default routes, in the `net` shadow
//! (LLD 3, sections 2 and 7; part 1 of the net module).
//!
//! The module reads the kernel's tables over rtnetlink ([`netlink`]) when it starts, then a
//! thread listens for changes to links, addresses and routes. A change starts a short quiet
//! period; when it ends (or 5 s after the first change, if changes keep coming) the module
//! reads everything again and reports the new snapshot, with a `net.changed` event naming what
//! differs. It also reads everything every minute, in case a change was missed.
//!
//! Read-only: it changes no interface, address or route, and needs no capability. The change
//! socket is read on its own thread, so registering it with tokio (an `unsafe` operation) isn't
//! needed.

pub(crate) mod netlink;
pub(crate) mod snapshot;

use std::collections::BTreeMap;
use std::future::pending;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{Module, ModuleContext, ModuleError, ModuleFuture};
use crate::mqtt::envelope::timestamp;
use netlink::{Kernel, Rtnetlink, Watch};

const MODULE: &str = "net";
/// How long the tables must be quiet after a change before they're read.
const QUIET: Duration = Duration::from_secs(1);
/// The longest a change waits to be reported while changes keep coming.
const MAX_DELAY: Duration = Duration::from_secs(5);
/// How often everything is read again, changes or not.
const RESYNC: Duration = Duration::from_secs(60);

/// `[modules.net]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetSettings {
    pub(crate) enabled: bool,
    /// Interface names to leave out; a trailing `*` matches a prefix.
    exclude: Vec<String>,
}

impl Default for NetSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            exclude: vec!["veth*".into()],
        }
    }
}

impl NetSettings {
    pub(crate) fn check(self) -> Result<Option<Self>, String> {
        for pattern in &self.exclude {
            let name = pattern.strip_suffix('*').unwrap_or(pattern);
            if name.is_empty()
                || name.len() > 15
                || name.contains(['*', '/', '\0'])
                || name.chars().any(char::is_whitespace)
            {
                return Err(format!(
                    "modules.net.exclude: {pattern:?} isn't an interface name or a prefix \
                     followed by *"
                ));
            }
        }
        Ok(self.enabled.then_some(self))
    }

    pub(crate) fn excludes(&self, name: &str) -> bool {
        self.exclude
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => name == pattern,
            })
    }
}

/// Reads the kernel's tables and builds the snapshot `helios net list` prints and the module
/// reports (without `since`, which only the module tracks).
///
/// # Errors
///
/// Netlink errors.
pub(crate) fn current(
    kernel: &dyn Kernel,
    sysfs: &std::path::Path,
    settings: &NetSettings,
) -> std::io::Result<snapshot::Snapshot> {
    let tables = netlink::read(kernel)?;
    Ok(snapshot::build(&tables, sysfs, settings))
}

/// The supervised net module.
pub struct NetModule {
    settings: NetSettings,
    kernel: Arc<dyn Kernel>,
}

impl NetModule {
    /// The module, reading the real kernel.
    #[must_use]
    pub fn new(settings: NetSettings) -> Self {
        Self {
            settings,
            kernel: Arc::new(Rtnetlink),
        }
    }

    #[cfg(test)]
    fn with_kernel(settings: NetSettings, kernel: Arc<dyn Kernel>) -> Self {
        Self { settings, kernel }
    }
}

impl Module for NetModule {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(self.watch(ctx))
    }
}

impl NetModule {
    async fn watch(&self, ctx: ModuleContext) -> Result<(), ModuleError> {
        let watch = self
            .kernel
            .watch()
            .map_err(|error| ModuleError(format!("can't listen for network changes: {error}")))?;
        let (changed, mut changes) = mpsc::channel(1);
        std::thread::Builder::new()
            .name("helios-net".into())
            .spawn(move || listen(watch, &changed))
            .map_err(|error| ModuleError(format!("can't start the network listener: {error}")))?;
        let mut reporter = Reporter::default();
        self.refresh(&ctx, &mut reporter).await?;
        let mut first_change: Option<Instant> = None;
        let mut quiet_until = Instant::now();
        let mut resync_at = Instant::now() + RESYNC;
        loop {
            let due = first_change.map(|first| quiet_until.min(first + MAX_DELAY));
            tokio::select! {
                () = ctx.cancel.cancelled() => return Ok(()),
                change = changes.recv() => {
                    if change.is_none() {
                        return Err(ModuleError("the network change listener stopped".into()));
                    }
                    let now = Instant::now();
                    first_change.get_or_insert(now);
                    quiet_until = now + QUIET;
                }
                () = sleep_until(due) => {
                    first_change = None;
                    self.refresh(&ctx, &mut reporter).await?;
                    resync_at = Instant::now() + RESYNC;
                }
                () = tokio::time::sleep_until(resync_at) => {
                    self.refresh(&ctx, &mut reporter).await?;
                    resync_at = Instant::now() + RESYNC;
                }
            }
        }
    }

    /// Reads everything and reports it if it changed.
    async fn refresh(
        &self,
        ctx: &ModuleContext,
        reporter: &mut Reporter,
    ) -> Result<(), ModuleError> {
        let kernel = Arc::clone(&self.kernel);
        let sysfs: PathBuf = ctx.sysfs.clone();
        let settings = self.settings.clone();
        let snapshot =
            tokio::task::spawn_blocking(move || current(kernel.as_ref(), &sysfs, &settings))
                .await
                .map_err(|error| ModuleError(format!("reading the network tables: {error}")))?
                .map_err(|error| ModuleError(format!("reading the network tables: {error}")))?;
        if let Some((reported, event)) = reporter.update(snapshot, SystemTime::now()) {
            ctx.shadows.report(MODULE, reported);
            if let Some(event) = event {
                ctx.mqtt.publish_event(MODULE, "net.changed", event);
            }
        }
        Ok(())
    }
}

/// The listener thread: tells the module about each change, until the module stops listening
/// or the socket fails.
fn listen(mut watch: Box<dyn Watch>, changed: &mpsc::Sender<()>) {
    while !changed.is_closed() {
        match watch.wait() {
            Ok(true) => {
                // A change already waiting covers this one.
                let _ = changed.try_send(());
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "network change socket failed");
                return;
            }
        }
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => pending().await,
    }
}

/// What was last reported, and when each interface's `oper_state` last changed.
#[derive(Default)]
struct Reporter {
    last: Option<Map<String, Value>>,
    since: BTreeMap<String, (Value, SystemTime)>,
    warned_truncated: bool,
}

impl Reporter {
    /// The report for `snapshot`, and the event for what changed since the last one, or `None`
    /// if nothing did.
    fn update(
        &mut self,
        snapshot: snapshot::Snapshot,
        now: SystemTime,
    ) -> Option<(Map<String, Value>, Option<Value>)> {
        if snapshot.truncated && !self.warned_truncated {
            tracing::warn!(
                "more network interfaces or addresses than the net shadow holds; some are left out"
            );
        }
        self.warned_truncated |= snapshot.truncated;
        let mut interfaces = snapshot.interfaces;
        let mut since = BTreeMap::new();
        for (name, interface) in &mut interfaces {
            let state = interface["oper_state"].clone();
            let at = match self.since.get(name) {
                Some((previous, at)) if *previous == state => *at,
                _ => now,
            };
            interface["since"] = json!(timestamp(at));
            since.insert(name.clone(), (state, at));
        }
        self.since = since;
        let mut reported = Map::new();
        reported.insert("interfaces".into(), Value::Object(interfaces));
        reported.insert("truncated".into(), json!(snapshot.truncated));
        if self.last.as_ref() == Some(&reported) {
            return None;
        }
        let event = self.last.as_ref().and_then(|last| changes(last, &reported));
        self.last = Some(reported.clone());
        Some((reported, event))
    }
}

/// `net.changed`: interfaces added and removed, and the fields that changed on the rest; `None`
/// if no interface changed (only `truncated` did).
fn changes(old: &Map<String, Value>, new: &Map<String, Value>) -> Option<Value> {
    let empty = Map::new();
    let interfaces = |report: &Map<String, Value>| {
        report
            .get("interfaces")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| empty.clone())
    };
    let (old, new) = (interfaces(old), interfaces(new));
    let added: Vec<&String> = new.keys().filter(|name| !old.contains_key(*name)).collect();
    let removed: Vec<&String> = old.keys().filter(|name| !new.contains_key(*name)).collect();
    let mut changed = Map::new();
    for (name, interface) in &new {
        let (Some(before), Some(after)) = (
            old.get(name).and_then(Value::as_object),
            interface.as_object(),
        ) else {
            continue;
        };
        let mut fields: Vec<&String> = after
            .keys()
            .chain(before.keys().filter(|field| !after.contains_key(*field)))
            .filter(|field| field.as_str() != "since" && before.get(*field) != after.get(*field))
            .collect();
        fields.sort();
        if !fields.is_empty() {
            changed.insert(name.clone(), json!(fields));
        }
    }
    (!added.is_empty() || !removed.is_empty() || !changed.is_empty())
        .then(|| json!({"added": added, "removed": removed, "changed": changed}))
}

#[cfg(test)]
mod tests;
