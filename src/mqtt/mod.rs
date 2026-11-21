//! MQTT to AWS IoT Core (LLD 2): topics, the message envelope, and the connection manager.

use std::time::Duration;

pub mod envelope;
pub mod helios_shadow;
pub mod manager;
mod queue;
pub mod shadow;
pub mod topics;

/// The `[mqtt]` settings (LLD 2, section 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttSettings {
    /// 8883, or 443 with ALPN `x-amzn-mqtt-ca` for networks that block 8883.
    pub port: u16,
    /// The MQTT keep-alive. AWS IoT allows 30 s to 1200 s.
    pub keep_alive: Duration,
    /// How many events the offline queue holds.
    pub queue_messages: usize,
}

/// The standard MQTT-over-TLS port.
pub const PORT_8883: u16 = 8883;
/// MQTT over TLS on 443, with ALPN `x-amzn-mqtt-ca`.
pub const PORT_443: u16 = 443;
/// The shortest keep-alive AWS IoT accepts.
pub const MIN_KEEP_ALIVE: Duration = Duration::from_secs(30);
/// The longest keep-alive AWS IoT accepts.
pub const MAX_KEEP_ALIVE: Duration = Duration::from_secs(1200);

impl Default for MqttSettings {
    fn default() -> Self {
        Self {
            port: PORT_8883,
            keep_alive: Duration::from_secs(60),
            queue_messages: 1000,
        }
    }
}
