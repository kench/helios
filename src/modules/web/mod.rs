//! The `web` module (LLD 13): the Helios console served by the board itself, for phones and
//! laptops on the same network, with no internet. It serves the console's files and a local
//! version of the Control API: the same paths and JSON as the cloud's, for this one device.
//!
//! So far it holds [`reports`], which reads the modules' reports into the Control API's
//! responses exactly as the cloud does (helios-contract's report vectors check both).

#[allow(
    dead_code,
    reason = "the local Control API that uses it comes with the web module (LLD 13, PR 3)"
)]
pub(crate) mod reports;
