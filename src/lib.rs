//! Helios on-device agent.
//!
//! Connects to AWS IoT Core over MQTT with a key held in a PKCS#11 token, reports state
//! through Device Shadow and runs the device modules. See the Helios High-Level Design for
//! the overall design and LLD 1 for the identity components.

pub mod identity;
