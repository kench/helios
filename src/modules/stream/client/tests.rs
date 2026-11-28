use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::open_destination;
use crate::identity::secrets::{self, POINT_LEN};
use crate::identity::testing::{THING_NAME, ca, ready_identity};

const URL: &str =
    "srtla://ingest.example.com:5000?streamid=publish/live/pocket&passphrase=a-passphrase-1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opens_a_destination_sealed_to_the_device_for_the_daemon() {
    let device_ca = ca("stream-client-test");
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, rustls::RootCertStore::empty()).await;
    let watch = identity.watch();
    let public: [u8; POINT_LEN] = match &*watch.borrow() {
        crate::identity::manager::IdentityState::Ready(ready) => URL_SAFE_NO_PAD
            .decode(ready.secrets.as_ref().unwrap().public_base64())
            .unwrap()
            .try_into()
            .unwrap(),
        other => panic!("not ready: {other:?}"),
    };
    let seal = |stream: &str, url: &str| {
        let ephemeral = p256::SecretKey::from_slice(&[0x44; 32]).unwrap();
        let (enc, ct) = secrets::seal(
            &public,
            &ephemeral,
            &secrets::info(THING_NAME),
            format!("stream.destination {stream}").as_bytes(),
            url.as_bytes(),
        );
        json!({"sealed": {"enc": URL_SAFE_NO_PAD.encode(enc), "ct": URL_SAFE_NO_PAD.encode(ct)}})
    };
    let args = |destination: Value| json!({"stream_id": "pocket", "profile": {"set": "hevc"}, "destination": {"set": destination}});

    // Opened: the URL goes on, the rest as it was.
    let opened = open_destination(Some(&watch), args(seal("pocket", URL)), false).await;
    assert_eq!(opened["destination"], json!({"set": {"url": URL}}));
    assert_eq!(opened["profile"], json!({"set": "hevc"}));

    // Sealed for another stream (the AAD), or garbage: refused by the daemon with the reason.
    for destination in [
        seal("other", URL),
        json!({"sealed": {"enc": "AAAA", "ct": "AAAA"}}),
    ] {
        let opened = open_destination(Some(&watch), args(destination), false).await;
        let reason = opened["destination"]["set"]["unreadable"].as_str();
        assert!(
            reason.is_some_and(|r| !r.contains("passphrase")),
            "{opened}"
        );
    }

    // No identity: nothing to open with.
    let opened = open_destination(None, args(seal("pocket", URL)), false).await;
    assert_eq!(
        opened["destination"]["set"]["unreadable"],
        "the device has no key for sealed secrets"
    );

    // A plain URL from the cloud: refused, never passed on.
    for plain in [json!({"url": URL}), json!({"unreadable": "nothing"})] {
        let opened = open_destination(Some(&watch), args(plain), false).await;
        assert_eq!(
            opened["destination"],
            json!({"set": {"unreadable": "a destination from the cloud must be sealed"}})
        );
    }

    // From Helios's own console (a local command), a plain URL goes on as it is; anything
    // else in it is still refused.
    let plain = args(json!({"url": URL}));
    assert_eq!(open_destination(None, plain.clone(), true).await, plain);
    let odd = open_destination(None, args(json!({"url": URL, "unreadable": "x"})), true).await;
    assert_eq!(
        odd["destination"],
        json!({"set": {"unreadable": "a destination from the cloud must be sealed"}})
    );

    // Not a well-formed sealed value, or no destination: unchanged, for the daemon to check.
    for untouched in [
        args(json!({"sealed": {"enc": "AAAA"}})),
        json!({"stream_id": "pocket", "bitrate": {"set": 3000}}),
    ] {
        assert_eq!(
            open_destination(Some(&watch), untouched.clone(), false).await,
            untouched
        );
    }
    identity_cancel.cancel();
}
