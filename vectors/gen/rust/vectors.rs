//! Cross-check of the vectors against meshcored's `localapi` crate.
//!
//! Copy this file to `crates/localapi/tests/vectors.rs` in a scratch copy of meshcored and run
//! `VECTORS_DIR=/path/to/meshcore-local-api/vectors cargo test -p localapi --test vectors`.
//! It uses only the crate's public functions plus `p256` for signing.

use base64::Engine;
use localapi::crypto::{decode_public_key, fingerprint, verify};
use localapi::{is_hashtag_name, is_region_name, parse_since};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn load(name: &str) -> Value {
    let dir = std::env::var("VECTORS_DIR").expect("set VECTORS_DIR to the vectors folder");
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{name}")).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn pairing_vectors() {
    let v = load("pairing.json");
    let key = &v["testKey"];
    let raw = decode_public_key(key["publicKey"].as_str().unwrap()).expect("test key decodes");
    assert_eq!(fingerprint(&raw), key["fingerprint"].as_str().unwrap());
    assert_eq!(fingerprint(&[0u8; 64]), v["fingerprintOfZeroBytes"]["fingerprint"].as_str().unwrap());

    let d = hex_bytes(key["privateScalarHex"].as_str().unwrap());
    let sk = SigningKey::from_slice(&d).unwrap();
    let pt = sk.verifying_key().to_encoded_point(false);
    assert_eq!(&pt.as_bytes()[1..], &raw[..], "scalar and public key agree");

    let other = decode_public_key(v["otherKey"]["publicKey"].as_str().unwrap()).unwrap();
    assert_eq!(fingerprint(&other), v["otherKey"]["fingerprint"].as_str().unwrap());

    for s in v["validSignatures"].as_array().unwrap() {
        let msg = s["message"].as_str().unwrap();
        for field in ["derBase64", "rawBase64", "highSRawBase64", "highSDerBase64"] {
            let sig = s[field].as_str().unwrap();
            assert!(verify(&raw, msg, sig), "{field} must verify for {msg}");
            assert!(!verify(&other, msg, sig), "{field} must fail against the other key");
        }
        // p256 signs with RFC 6979, so it must reproduce r and s exactly.
        let sig: Signature = sk.sign(msg.as_bytes());
        let bytes = sig.to_bytes();
        assert_eq!(hex(&bytes[..32]), s["rHex"].as_str().unwrap(), "r for {msg}");
        assert_eq!(hex(&bytes[32..]), s["sHex"].as_str().unwrap(), "s for {msg}");
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
            s["derBase64"].as_str().unwrap()
        );
        assert_eq!(hex(&Sha256::digest(msg.as_bytes())), s["sha256Hex"].as_str().unwrap());
    }

    let inv = &v["invalidSignatures"];
    let msg = inv["message"].as_str().unwrap();
    for c in inv["cases"].as_array().unwrap() {
        let sig = c["signatureBase64"].as_str().unwrap();
        assert!(!verify(&raw, msg, sig), "must be refused: {}", c["why"]);
    }

    for c in v["invalidPublicKeys"].as_array().unwrap() {
        assert!(decode_public_key(c["publicKey"].as_str().unwrap()).is_none(), "must be refused: {}", c["why"]);
    }
    let _ = b64(key["publicKey"].as_str().unwrap());
}

#[test]
fn validator_vectors() {
    let v = load("validators.json");
    for c in v["hashtagChannelNames"]["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert_eq!(is_hashtag_name(name), c["valid"].as_bool().unwrap(), "hashtag {name:?}");
    }
    for c in v["hashtagChannelKeys"]["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert_eq!(hex(&Sha256::digest(name.as_bytes())[..16]), c["keyHex"].as_str().unwrap());
    }
    for c in v["regionNames"]["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        assert_eq!(is_region_name(name), c["wellFormed"].as_bool().unwrap(), "region {name:?}");
    }
    for c in v["since"]["cases"].as_array().unwrap() {
        let got = parse_since(&c["since"]);
        match c.get("epochMs") {
            Some(ms) => assert_eq!(got.ok(), ms.as_i64(), "since {}", c["since"]),
            None => assert!(got.is_err(), "since {} must be refused", c["since"]),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn region_vectors() {
    let v = load("regions.json");
    let cat = localapi::regions::RegionCatalog::from_json(&serde_json::json!({"regions": v["catalogue"]}).to_string()).unwrap();
    for c in v["cases"].as_array().unwrap() {
        let got = cat.resolve(c["lat"].as_f64().unwrap(), c["lon"].as_f64().unwrap());
        match c["region"].as_str() {
            Some(name) => {
                let (r, d) = got.expect("a region");
                assert_eq!(r.name, name, "{}", c["why"]);
                assert!((d - c["distanceKm"].as_f64().unwrap()).abs() < 0.001, "{}", c["why"]);
            }
            None => assert!(got.is_none(), "{}", c["why"]),
        }
    }
}
