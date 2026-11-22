use super::*;

const FAMILY: u16 = 0x22;

fn reply(family: u16, flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
    message(family, flags, 0, &attributes.concat())
}

fn done() -> Vec<u8> {
    let mut done = message(NLMSG_DONE, 0x2, 0, &[]);
    done.truncate(NLMSG_HDR_LEN);
    done.extend_from_slice(&0u32.to_ne_bytes());
    let len = u32::try_from(done.len()).unwrap();
    done[..4].copy_from_slice(&len.to_ne_bytes());
    done
}

#[test]
fn builds_generic_netlink_requests() {
    let request = message(
        FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        NL80211_CMD_GET_STATION,
        &attribute(NL80211_ATTR_IFINDEX, &4u32.to_ne_bytes()),
    );
    assert_eq!(request.len(), NLMSG_HDR_LEN + GENL_HDR_LEN + 8);
    assert_eq!(u16::from_ne_bytes([request[4], request[5]]), FAMILY);
    assert_eq!(request[16], NL80211_CMD_GET_STATION);
    assert_eq!(request[17], 1, "version");
    // The attribute: length 8, type IFINDEX, value 4.
    assert_eq!(&request[20..24], [8, 0, 3, 0]);
    assert_eq!(&request[24..28], 4u32.to_ne_bytes());
    // An odd-length value is padded.
    assert_eq!(attribute(2, b"nl80211\0").len(), 12);
    assert_eq!(attribute(2, b"abc").len(), 8);
}

#[test]
fn finds_the_family_id() {
    let id = reply(
        GENL_ID_CTRL,
        0,
        &[
            attribute(CTRL_ATTR_FAMILY_NAME, b"nl80211\0"),
            attribute(CTRL_ATTR_FAMILY_ID, &FAMILY.to_ne_bytes()),
        ],
    );
    assert_eq!(parse_family(&[id]).unwrap(), Some(FAMILY));
    let without = reply(GENL_ID_CTRL, 0, &[attribute(CTRL_ATTR_FAMILY_NAME, b"x\0")]);
    assert_eq!(parse_family(&[without]).unwrap(), None);
}

#[test]
fn reads_the_joined_network() {
    let interface = reply(
        FAMILY,
        0,
        &[
            attribute(NL80211_ATTR_IFINDEX, &4u32.to_ne_bytes()),
            attribute(NL80211_ATTR_SSID, b"Home"),
            attribute(NL80211_ATTR_WIPHY_FREQ, &5240u32.to_ne_bytes()),
        ],
    );
    assert_eq!(
        parse_interface(&[interface], FAMILY).unwrap(),
        Some(("Home".to_owned(), Some(5240)))
    );
    // Not joined: no SSID (or an empty one).
    let idle = reply(
        FAMILY,
        0,
        &[attribute(NL80211_ATTR_IFINDEX, &4u32.to_ne_bytes())],
    );
    assert_eq!(parse_interface(&[idle], FAMILY).unwrap(), None);
    let empty = reply(FAMILY, 0, &[attribute(NL80211_ATTR_SSID, b"")]);
    assert_eq!(parse_interface(&[empty], FAMILY).unwrap(), None);
    // Messages of another family are skipped.
    let other = reply(0x30, 0, &[attribute(NL80211_ATTR_SSID, b"x")]);
    assert_eq!(parse_interface(&[other], FAMILY).unwrap(), None);
}

#[test]
fn reads_the_access_point_and_its_signal() {
    let info = |signal: Option<i8>, average: Option<i8>| {
        let mut nested = Vec::new();
        if let Some(signal) = signal {
            nested.extend(attribute(NL80211_STA_INFO_SIGNAL, &signal.to_ne_bytes()));
        }
        if let Some(average) = average {
            nested.extend(attribute(
                NL80211_STA_INFO_SIGNAL_AVG,
                &average.to_ne_bytes(),
            ));
        }
        nested.extend(attribute(99, &[1, 2, 3, 4]));
        attribute(NL80211_ATTR_STA_INFO, &nested)
    };
    let ap = [0x8a, 0x78, 0x48, 0xfe, 0x86, 0x5a];
    let station = reply(
        FAMILY,
        0x2,
        &[attribute(NL80211_ATTR_MAC, &ap), info(Some(-47), Some(-45))],
    );
    assert_eq!(
        parse_station(&[station, done()], FAMILY).unwrap(),
        (Some(ap), Some(-45)),
        "the average when there is one"
    );
    let station = reply(
        FAMILY,
        0x2,
        &[attribute(NL80211_ATTR_MAC, &ap), info(Some(-71), None)],
    );
    assert_eq!(
        parse_station(&[station], FAMILY).unwrap(),
        (Some(ap), Some(-71))
    );
    let bare = reply(FAMILY, 0x2, &[attribute(NL80211_ATTR_MAC, &[1, 2, 3])]);
    assert_eq!(parse_station(&[bare], FAMILY).unwrap(), (None, None));
    assert_eq!(parse_station(&[done()], FAMILY).unwrap(), (None, None));
    let broken = reply(
        FAMILY,
        0x2,
        &[attribute(NL80211_ATTR_STA_INFO, &[200, 0, 7, 0])],
    );
    assert!(parse_station(&[broken], FAMILY).is_err());
}

#[test]
fn a_message_too_short_for_its_generic_header_is_an_error() {
    let mut short = message(FAMILY, 0, 0, &[]);
    short.truncate(NLMSG_HDR_LEN + 2);
    let len = u32::try_from(short.len()).unwrap();
    short[..4].copy_from_slice(&len.to_ne_bytes());
    assert!(parse_interface(&[short], FAMILY).is_err());
}

#[test]
fn asks_this_machines_kernel() {
    // Loopback isn't Wi-Fi; a missing interface isn't either. Works with or without cfg80211.
    assert_eq!(Nl80211.link(1).unwrap(), None);
    assert_eq!(Nl80211.link(999_999).unwrap(), None);
    assert_eq!(NoWireless.link(1).unwrap(), None);
}
