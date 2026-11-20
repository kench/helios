//! Process hardening at startup (LLD 1, section 4.5).

use rustix::process::DumpableBehavior;

/// Marks the process as not dumpable (`prctl(PR_SET_DUMPABLE, 0)`), so the PIN, credentials
/// and other secrets in memory can't end up in a core dump, and other processes of the same
/// user can't attach to it. The systemd unit also sets `LimitCORE=0`.
///
/// # Errors
///
/// Fails if the kernel rejects the call.
pub fn disable_core_dumps() -> std::io::Result<()> {
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    Ok(())
}

/// Whether the process is currently marked as not dumpable.
///
/// # Errors
///
/// Fails if the kernel rejects the call.
pub fn core_dumps_disabled() -> std::io::Result<bool> {
    Ok(rustix::process::dumpable_behavior()? == DumpableBehavior::NotDumpable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disables_core_dumps() {
        disable_core_dumps().unwrap();

        assert!(core_dumps_disabled().unwrap());
    }
}
