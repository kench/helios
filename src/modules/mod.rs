//! Device modules (HLD section 6), each turned on by its `[modules.<name>]` config section.
//!
//! - `display`: screens on the scanner's framebuffer (LLD 9).
//!
//! The shared module framework (LLD 8, section 3) comes with the next module; until then the
//! service starts each module directly.

pub mod display;
