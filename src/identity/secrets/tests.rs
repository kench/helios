use p256::elliptic_curve::sec1::ToSec1Point;

use super::*;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn point(text: &str) -> [u8; POINT_LEN] {
    hex(text).try_into().unwrap()
}

/// RFC 9180, appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
mod rfc9180 {
    pub const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    pub const PK_EM: &str = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";
    pub const SK_EM: &str = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";
    pub const PK_RM: &str = "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";
    pub const SK_RM: &str = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";
    pub const KEY: &str = "868c066ef58aae6dc589b6cfdd18f97e";
    pub const BASE_NONCE: &str = "4e0bc5018beba4bf004cca59";
    pub const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    pub const AAD_0: &str = "436f756e742d30";
    pub const CT_0: &str = "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434";
}

fn recipient() -> p256::SecretKey {
    p256::SecretKey::from_slice(&hex(rfc9180::SK_RM)).unwrap()
}

/// The DH secret as the token computes it: the x-coordinate of `skR * peer`.
fn dh(secret: &p256::SecretKey, peer: &[u8; POINT_LEN]) -> Vec<u8> {
    let peer = p256::PublicKey::from_sec1_bytes(peer).unwrap();
    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine())
        .raw_secret_bytes()
        .to_vec()
}

#[test]
fn the_key_schedule_matches_rfc_9180() {
    let public = point(rfc9180::PK_RM);
    let enc = point(rfc9180::PK_EM);
    assert_eq!(
        recipient().public_key().to_sec1_point(false).as_bytes(),
        public,
        "the vector's key pair"
    );
    let (key, nonce) = key_schedule(&dh(&recipient(), &enc), &public, &enc, &hex(rfc9180::INFO));
    assert_eq!(key.as_slice(), hex(rfc9180::KEY));
    assert_eq!(nonce.as_slice(), hex(rfc9180::BASE_NONCE));
}

#[test]
fn opens_rfc_9180s_first_encryption() {
    let public = point(rfc9180::PK_RM);
    let enc = point(rfc9180::PK_EM);
    let plaintext = open_with(
        &dh(&recipient(), &enc),
        &public,
        &enc,
        &hex(rfc9180::INFO),
        &hex(rfc9180::AAD_0),
        &hex(rfc9180::CT_0),
    )
    .unwrap();
    assert_eq!(plaintext.as_slice(), hex(rfc9180::PT));
    assert_eq!(plaintext.as_slice(), b"Beauty is truth, truth beauty");
}

#[test]
fn seals_as_rfc_9180_does() {
    let ephemeral = p256::SecretKey::from_slice(&hex(rfc9180::SK_EM)).unwrap();
    let (enc, ct) = seal(
        &point(rfc9180::PK_RM),
        &ephemeral,
        &hex(rfc9180::INFO),
        &hex(rfc9180::AAD_0),
        &hex(rfc9180::PT),
    );
    assert_eq!(enc, point(rfc9180::PK_EM));
    assert_eq!(ct, hex(rfc9180::CT_0));
}

#[test]
fn refuses_what_doesnt_authenticate() {
    let public = point(rfc9180::PK_RM);
    let enc = point(rfc9180::PK_EM);
    let shared = dh(&recipient(), &enc);
    let info = hex(rfc9180::INFO);
    let ct = hex(rfc9180::CT_0);
    // Another purpose, another device, an altered ciphertext, another key.
    for (info, aad, ct) in [
        (info.clone(), b"Count-1".to_vec(), ct.clone()),
        (
            b"helios secret v1 t-other".to_vec(),
            hex(rfc9180::AAD_0),
            ct.clone(),
        ),
        (info.clone(), hex(rfc9180::AAD_0), {
            let mut altered = ct.clone();
            altered[0] ^= 1;
            altered
        }),
    ] {
        assert_eq!(
            open_with(&shared, &public, &enc, &info, &aad, &ct).unwrap_err(),
            SecretError::Unreadable
        );
    }
    let other = p256::SecretKey::from_slice(&[7; 32]).unwrap();
    assert_eq!(
        open_with(
            &dh(&other, &enc),
            &public,
            &enc,
            &info,
            &hex(rfc9180::AAD_0),
            &ct
        )
        .unwrap_err(),
        SecretError::Unreadable
    );
}

#[test]
fn decodes_the_wire_form() {
    let sealed = |enc: &str, ct: &str| Sealed {
        enc: enc.into(),
        ct: ct.into(),
    };
    let enc = URL_SAFE_NO_PAD.encode(point(rfc9180::PK_EM));
    let (decoded, ct) = decode(&sealed(&enc, "AAEC")).unwrap();
    assert_eq!(decoded, point(rfc9180::PK_EM));
    assert_eq!(ct, [0, 1, 2]);
    let mut compressed = point(rfc9180::PK_EM);
    compressed[0] = 0x02;
    for (bad, why) in [
        (sealed("not base64!", "AAEC"), "enc isn't base64url"),
        (
            sealed("AAEC", "AAEC"),
            "enc isn't an uncompressed P-256 point",
        ),
        (
            sealed(&URL_SAFE_NO_PAD.encode(compressed), "AAEC"),
            "enc isn't an uncompressed P-256 point",
        ),
        (sealed(&enc, "***"), "ct isn't base64url"),
        (sealed(&enc, &"A".repeat(6000)), "ct is too long"),
    ] {
        assert_eq!(decode(&bad).unwrap_err(), SecretError::Malformed(why));
    }
    assert_eq!(format!("{:?}", sealed(&enc, "AAEC")), "Sealed(..)");
    assert_eq!(info("t-01M80KAX"), b"helios secret v1 t-01M80KAX");
    assert_eq!(SecretError::Unreadable.code(), "SECRET_UNREADABLE");
    assert_eq!(
        SecretError::from(TokenError::NotOpen),
        SecretError::Token(TokenError::NotOpen.to_string())
    );
}
