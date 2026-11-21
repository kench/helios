//! Topic names (LLD 2, section 2). The device IoT policy allows exactly these, scoped to the
//! connecting thing.

/// The module lifecycle events are published under.
pub const LIFECYCLE: &str = "lifecycle";

/// Events: `helios/<thing>/evt/<module>`.
#[must_use]
pub fn event(thing: &str, module: &str) -> String {
    format!("helios/{thing}/evt/{module}")
}

/// The filters each session subscribes to, in one SUBSCRIBE (AWS IoT allows 8 per request):
/// commands (custom-topics transport) and the named shadows' replies and deltas.
#[must_use]
pub fn session_filters(thing: &str) -> Vec<String> {
    let shadows = format!("$aws/things/{thing}/shadow/name/+");
    vec![
        format!("helios/{thing}/cmd/+"),
        format!("{shadows}/update/accepted"),
        format!("{shadows}/update/rejected"),
        format!("{shadows}/update/delta"),
        format!("{shadows}/get/accepted"),
        format!("{shadows}/get/rejected"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_topics() {
        assert_eq!(event("t-1", LIFECYCLE), "helios/t-1/evt/lifecycle");
        let filters = session_filters("t-1");
        assert_eq!(filters.len(), 6);
        assert_eq!(filters[0], "helios/t-1/cmd/+");
        assert_eq!(filters[3], "$aws/things/t-1/shadow/name/+/update/delta");
    }

    #[test]
    fn stays_within_aws_iot_limits() {
        // 256 bytes and at most 7 slashes per topic filter.
        let thing = "t-01M7Y7K4GVVSN6PX39F0NWAF4F";
        for filter in session_filters(thing) {
            assert!(filter.len() <= 256, "{filter}");
            assert!(filter.matches('/').count() <= 7, "{filter}");
        }
        assert!(session_filters(thing).len() <= 8);
    }
}
