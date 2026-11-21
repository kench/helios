//! The message envelope for `evt`, `cmd` and `rsp` messages (LLD 2, section 3).

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The envelope version Helios writes.
pub const VERSION: u32 = 1;

/// One message's envelope. Receivers ignore fields they don't know.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// The envelope version.
    pub v: u32,
    /// A ULID, unique per message.
    pub id: String,
    /// On a response: the command's `id`.
    pub correlation_id: Option<String>,
    /// RFC 3339 UTC with milliseconds, by the device clock.
    pub ts: String,
    /// The sender's or target's thing name.
    pub thing: String,
    /// The module, as in the topic.
    pub module: String,
    /// `<module>.<name>`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Per `type`.
    pub payload: Value,
    /// Responses only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Responses with `status: error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// A response's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The command succeeded.
    Ok,
    /// The command failed; see `error`.
    Error,
    /// The command didn't finish in time.
    Timeout,
}

/// A response's error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Upper snake case, such as `UNKNOWN_COMMAND`.
    pub code: String,
    /// For people.
    pub message: String,
}

impl Envelope {
    /// An event from `thing` at `time`, with a new ID.
    #[must_use]
    pub fn event(thing: &str, module: &str, kind: &str, payload: Value, time: SystemTime) -> Self {
        Self {
            v: VERSION,
            id: crate::ulid::new(time),
            correlation_id: None,
            ts: timestamp(time),
            thing: thing.to_owned(),
            module: module.to_owned(),
            kind: kind.to_owned(),
            payload,
            status: None,
            error: None,
        }
    }

    /// The envelope as JSON bytes.
    ///
    /// # Panics
    ///
    /// Never: an envelope always serializes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("an envelope always serializes")
    }
}

/// `time` as RFC 3339 UTC with milliseconds, such as `2026-11-21T05:05:07.363Z`. Times before
/// 1970 are written as the epoch.
#[must_use]
pub fn timestamp(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// Parses an RFC 3339 UTC timestamp as written by [`timestamp`]: `YYYY-MM-DDTHH:MM:SS`, an
/// optional fraction of a second, and `Z`. Other offsets aren't accepted.
#[must_use]
pub fn parse_timestamp(text: &str) -> Option<SystemTime> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.splitn(3, '-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = clock.splitn(3, ':');
    let hour: u64 = clock.next()?.parse().ok()?;
    let minute: u64 = clock.next()?.parse().ok()?;
    let second: u64 = clock.next()?.parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let nanos = format!("{fraction:0<9}").get(..9)?.parse::<u32>().ok()?;
    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + std::time::Duration::new(secs, nanos))
}

/// Days from 1970-01-01 to the proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date `days` after 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    #[test]
    fn writes_rfc3339_with_milliseconds() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let time = UNIX_EPOCH + Duration::from_millis(1_795_237_507_363);
        assert_eq!(timestamp(time), "2026-11-21T05:05:07.363Z");
        // A leap day.
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(timestamp(leap), "2000-02-29T00:00:00.000Z");
        assert_eq!(
            timestamp(UNIX_EPOCH - Duration::from_secs(1)),
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn parses_what_it_writes() {
        let time = UNIX_EPOCH + Duration::from_millis(1_795_237_507_363);

        assert_eq!(parse_timestamp(&timestamp(time)), Some(time));
        assert_eq!(
            parse_timestamp("2000-02-29T00:00:00Z"),
            Some(UNIX_EPOCH + Duration::from_secs(951_782_400))
        );
        assert_eq!(
            parse_timestamp("2026-11-21T05:05:07.5Z"),
            Some(UNIX_EPOCH + Duration::from_millis(1_795_237_507_500))
        );
    }

    #[test]
    fn rejects_other_forms() {
        for text in [
            "2026-11-21T05:05:07+01:00",
            "2026-11-21 05:05:07Z",
            "2026-13-01T00:00:00Z",
            "2026-11-21T24:00:00Z",
            "2026-11-21T05:05:07.x1Z",
            "1969-12-31T23:59:59Z",
            "nonsense",
        ] {
            assert_eq!(parse_timestamp(text), None, "{text}");
        }
    }

    #[test]
    fn an_event_round_trips_as_json() {
        let time = UNIX_EPOCH + Duration::from_secs(1_795_237_507);
        let event = Envelope::event(
            "t-1",
            "lifecycle",
            "lifecycle.online",
            json!({"session": 1}),
            time,
        );

        let json: Value = serde_json::from_slice(&event.to_bytes()).unwrap();

        assert_eq!(json["v"], 1);
        assert_eq!(json["type"], "lifecycle.online");
        assert_eq!(json["correlation_id"], Value::Null);
        assert_eq!(json["ts"], "2026-11-21T05:05:07.000Z");
        assert!(json.get("status").is_none());
        assert_eq!(serde_json::from_value::<Envelope>(json).unwrap(), event);
    }

    #[test]
    fn reads_responses_and_ignores_unknown_fields() {
        let response: Envelope = serde_json::from_value(json!({
            "v": 1, "id": "01", "correlation_id": "00", "ts": "2026-11-21T05:05:07.000Z",
            "thing": "t-1", "module": "video", "type": "video.stream.start", "payload": {},
            "status": "error", "error": {"code": "TIMEOUT", "message": "late"}, "extra": true
        }))
        .unwrap();

        assert_eq!(response.status, Some(Status::Error));
        assert_eq!(response.error.unwrap().code, "TIMEOUT");
    }
}
