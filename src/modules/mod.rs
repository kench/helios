//! Device modules (HLD section 6), each turned on by its `[modules.<name>]` config section.
//!
//! - `display`: screens on the scanner's framebuffer (LLD 9).
//!
//! Each module is behind a Cargo feature (`module-display`), off by default, so a device's build
//! carries only the modules it uses. In a build without it, the module's config section is
//! reported as unused, like any other unknown section.
//!
//! The shared module framework (LLD 8, section 3) comes with the next module; until then the
//! service starts each module directly.

#[cfg(feature = "module-display")]
pub mod display;
