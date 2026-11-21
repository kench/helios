//! Logging for the service: `tracing` events as text on stderr, which systemd sends to
//! journald (HLD section 11).
//!
//! The level comes from `HELIOS_LOG` (`error`, `warn`, `info`, `debug` or `trace`; default
//! `info`). Under journald (`JOURNAL_STREAM` set), timestamps are left out because journald
//! adds its own. Secrets never reach the log: the types that hold them don't print them.

use std::str::FromStr;

use tracing::level_filters::LevelFilter;

/// The environment variable that sets the log level.
pub const LEVEL_VAR: &str = "HELIOS_LOG";

/// The level to log at for a `HELIOS_LOG` value, and a complaint if the value isn't one.
#[must_use]
pub fn level(value: Option<&str>) -> (LevelFilter, Option<String>) {
    match value.map(str::trim) {
        None | Some("") => (LevelFilter::INFO, None),
        Some(value) => match LevelFilter::from_str(value) {
            Ok(level) => (level, None),
            Err(_) => (
                LevelFilter::INFO,
                Some(format!(
                    "{LEVEL_VAR}={value:?} is not a log level (error, warn, info, debug, trace, \
                     off); using info"
                )),
            ),
        },
    }
}

/// Installs the stderr subscriber for the process. Does nothing if one is already installed.
pub fn init() {
    let value = std::env::var(LEVEL_VAR).ok();
    let (level, complaint) = level(value.as_deref());
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .with_max_level(level);
    let installed = if std::env::var_os("JOURNAL_STREAM").is_some() {
        builder.without_time().try_init()
    } else {
        builder.try_init()
    };
    if installed.is_ok()
        && let Some(complaint) = complaint
    {
        tracing::warn!("{complaint}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_info() {
        assert_eq!(level(None), (LevelFilter::INFO, None));
        assert_eq!(level(Some(" ")), (LevelFilter::INFO, None));
    }

    #[test]
    fn reads_the_level() {
        assert_eq!(level(Some("debug")), (LevelFilter::DEBUG, None));
        assert_eq!(level(Some("WARN")), (LevelFilter::WARN, None));
        assert_eq!(level(Some("off")), (LevelFilter::OFF, None));
    }

    #[test]
    fn falls_back_to_info_for_nonsense() {
        let (filter, complaint) = level(Some("loud"));
        assert_eq!(filter, LevelFilter::INFO);
        assert!(complaint.unwrap().contains("\"loud\""));
    }

    #[test]
    fn init_twice_is_harmless() {
        init();
        init();
        tracing::info!("logging works");
    }
}
