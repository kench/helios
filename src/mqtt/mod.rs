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
    /// How often the `helios` shadow may be updated for changes that aren't urgent.
    pub helios_shadow_interval: Duration,
    /// The command transports to listen on (LLD 2, section 7): `mqtt.commands`.
    pub commands: CommandTransports,
}

/// Which command transports Helios listens on (`mqtt.commands`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandTransports {
    /// Helios's own `helios/<thing>/cmd/<module>` topics (LLD 2, section 7.2).
    pub topics: bool,
    /// AWS IoT command executions (section 7.3).
    pub aws_iot_commands: bool,
}

impl Default for CommandTransports {
    /// Both: custom topics for existing tools, AWS IoT commands for the Control API.
    fn default() -> Self {
        Self {
            topics: true,
            aws_iot_commands: true,
        }
    }
}

impl CommandTransports {
    /// The transport these make, listening on each one chosen.
    #[must_use]
    pub fn transport(self) -> std::sync::Arc<dyn crate::router::CommandTransport> {
        let mut transports: Vec<std::sync::Arc<dyn crate::router::CommandTransport>> = Vec::new();
        if self.topics {
            transports.push(std::sync::Arc::new(crate::router::topics::TopicsTransport));
        }
        if self.aws_iot_commands {
            transports.push(std::sync::Arc::new(
                crate::router::aws_commands::AwsCommandsTransport,
            ));
        }
        std::sync::Arc::new(crate::router::aws_commands::Transports::new(transports))
    }
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
            helios_shadow_interval: crate::mqtt::helios_shadow::DEFAULT_INTERVAL,
            commands: CommandTransports::default(),
        }
    }
}
