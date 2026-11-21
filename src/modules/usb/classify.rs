pub(super) fn interface(
    class: Option<u16>,
    driver: Option<&str>,
) -> impl Iterator<Item = &'static str> {
    let category = match class {
        Some(1) => Some("audio"),
        Some(8) => Some("storage"),
        Some(11) => Some("smartcard"),
        Some(14) => Some("video"),
        _ => None,
    };
    category
        .into_iter()
        .chain(is_wwan_driver(driver).then_some("cellular"))
}

pub(super) fn network(
    wifi: bool,
    wwan: bool,
    driver: Option<&str>,
    hardware_type: Option<&str>,
) -> Option<&'static str> {
    if wifi {
        Some("wifi")
    } else if wwan || is_wwan_driver(driver) {
        Some("cellular")
    } else if hardware_type == Some("1") {
        Some("ethernet")
    } else {
        None
    }
}

fn is_wwan_driver(driver: Option<&str>) -> bool {
    matches!(driver, Some("qmi_wwan" | "cdc_mbim"))
}
