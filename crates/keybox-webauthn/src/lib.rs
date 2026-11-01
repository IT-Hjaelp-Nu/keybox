//! Passkey verification for Key-Box.
//!
//! This is a deliberately narrow WebAuthn relying party. It accepts exactly
//! what Key-Box uses and refuses everything else:
//!
//! - ES256 (ECDSA P-256 with SHA-256) keys only.
//! - User verification is always required (biometrics or PIN on the device).
//! - No attestation, no extensions.
//!
//! A signature is only ever accepted for one [`Site`] (the origin and RP ID of
//! Key-Box' own approval page) and one challenge. For an approval the
//! challenge is derived from the request itself with [`approval_challenge`],
//! so the passkey signs that request and no other.
//!
//! References are to WebAuthn Level 2, sections 6.1, 6.5, 7.1 and 7.2.

#![forbid(unsafe_code)]

use std::fmt;

use ring::digest::{SHA256, digest};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde::Deserialize;

pub const MAX_CLIENT_DATA_BYTES: usize = 4096;
pub const MAX_AUTH_DATA_BYTES: usize = 2048;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_ATTESTED_DATA: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;

/// rpIdHash (32) + flags (1) + signCount (4).
const AUTH_DATA_HEADER: usize = 37;
/// An uncompressed P-256 point: 0x04, X, Y.
pub const PUBLIC_KEY_BYTES: usize = 65;

/// Why a passkey response was refused. Fixed words only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    TooLarge,
    /// clientDataJSON is not what a browser produces.
    ClientData,
    /// Made for registration when a signature was expected, or the reverse.
    WrongType,
    /// Not an answer to the challenge Key-Box issued.
    WrongChallenge,
    /// Produced on another site.
    WrongOrigin,
    CrossOrigin,
    /// authenticatorData is too short, too long or has data we do not accept.
    AuthData,
    /// The passkey belongs to another site.
    WrongRpId,
    UserNotPresent,
    /// No biometrics or PIN was used.
    UserNotVerified,
    /// Not an ES256 key in the standard encoding.
    UnsupportedKey,
    BadSignature,
    /// The signature counter went backwards: the passkey may have been copied.
    CounterWentBack,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Refused {}

/// Key-Box' approval page, as the browser and the passkey see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// The page's origin exactly as the browser reports it, e.g.
    /// `https://keybox.example.ts.net`.
    pub origin: String,
    /// The domain the passkeys are bound to, e.g. `keybox.example.ts.net`.
    pub rp_id: String,
}

/// A newly registered passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub sign_count: u32,
    /// The passkey can be synced to other devices by its provider.
    pub backup_eligible: bool,
}

/// The challenge a passkey must sign to approve a request: a hash of a fresh
/// random nonce and the request's binding. The nonce makes it single use; the
/// binding ties it to exactly that request.
pub fn approval_challenge(nonce: &[u8; 32], binding: &[u8]) -> [u8; 32] {
    let mut input = b"keybox-approval-v1\0".to_vec();
    input.extend_from_slice(nonce);
    input.extend_from_slice(binding);
    sha256(&input)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, data).as_ref());
    out
}

/// Base64url without padding, as browsers encode the challenge.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
        }
    }
    out
}

/// Strict inverse of [`base64url`]: only the alphabet, no padding, no
/// leftover bits. `None` for anything else.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    for chunk in text.as_bytes().chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for c in chunk {
            n = (n << 6) | u32::from(value(*c)?);
        }
        n <<= 6 * (4 - chunk.len());
        let bytes = n.to_be_bytes();
        // Bits that do not belong to a whole byte must be zero.
        if bytes[chunk.len()..].iter().any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

/// Steps 7.1.5–7.1.9 / 7.2.10–7.2.13: the browser's own statement of what it
/// was asked to sign, and for which site.
fn check_client_data(
    json: &[u8],
    kind: &str,
    challenge: &[u8],
    site: &Site,
) -> Result<(), Refused> {
    if json.len() > MAX_CLIENT_DATA_BYTES {
        return Err(Refused::TooLarge);
    }
    let data: ClientData = serde_json::from_slice(json).map_err(|_| Refused::ClientData)?;
    if data.kind != kind {
        return Err(Refused::WrongType);
    }
    if data.challenge != base64url(challenge) {
        return Err(Refused::WrongChallenge);
    }
    if data.origin != site.origin {
        return Err(Refused::WrongOrigin);
    }
    if data.cross_origin {
        return Err(Refused::CrossOrigin);
    }
    Ok(())
}

/// The fixed start of authenticatorData. Returns the flags, the counter and
/// whatever follows the header.
fn check_auth_data<'a>(auth_data: &'a [u8], site: &Site) -> Result<(u8, u32, &'a [u8]), Refused> {
    if auth_data.len() > MAX_AUTH_DATA_BYTES {
        return Err(Refused::TooLarge);
    }
    let Some((header, rest)) = auth_data.split_at_checked(AUTH_DATA_HEADER) else {
        return Err(Refused::AuthData);
    };
    if header[..32] != sha256(site.rp_id.as_bytes()) {
        return Err(Refused::WrongRpId);
    }
    let flags = header[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(Refused::UserNotPresent);
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(Refused::UserNotVerified);
    }
    // Key-Box asks for no extensions, so none may come back.
    if flags & FLAG_EXTENSIONS != 0 {
        return Err(Refused::AuthData);
    }
    let count = u32::from_be_bytes([header[33], header[34], header[35], header[36]]);
    Ok((flags, count, rest))
}

/// Verify the answer to `navigator.credentials.create()`.
///
/// `auth_data` is what the browser returns from `getAuthenticatorData()`.
/// There is no attestation: Key-Box trusts a new passkey because the person
/// registering it holds the console token or an existing passkey, not because
/// of who made the authenticator.
pub fn verify_registration(
    site: &Site,
    challenge: &[u8],
    client_data_json: &[u8],
    auth_data: &[u8],
) -> Result<Registered, Refused> {
    check_client_data(client_data_json, "webauthn.create", challenge, site)?;
    let (flags, sign_count, rest) = check_auth_data(auth_data, site)?;
    if flags & FLAG_ATTESTED_DATA == 0 {
        return Err(Refused::AuthData);
    }
    // Attested credential data (6.5.1): AAGUID (16), id length (2), id, key.
    let Some((prefix, rest)) = rest.split_at_checked(18) else {
        return Err(Refused::AuthData);
    };
    let id_len = usize::from(u16::from_be_bytes([prefix[16], prefix[17]]));
    if id_len == 0 || id_len > MAX_CREDENTIAL_ID_BYTES {
        return Err(Refused::AuthData);
    }
    let Some((credential_id, key)) = rest.split_at_checked(id_len) else {
        return Err(Refused::AuthData);
    };
    Ok(Registered {
        credential_id: credential_id.to_vec(),
        public_key: es256_key(key)?,
        sign_count,
        backup_eligible: flags & FLAG_BACKUP_ELIGIBLE != 0,
    })
}

/// The one key encoding accepted: a COSE EC2 key for ES256 on P-256 in CTAP2
/// canonical form, which is 77 bytes laid out exactly like this. Matching the
/// bytes instead of parsing CBOR means nothing else can get through.
///
/// ```text
/// a5            map of 5
/// 01 02         kty: EC2
/// 03 26         alg: ES256 (-7)
/// 20 01         crv: P-256
/// 21 58 20 <X>  x: 32 bytes
/// 22 58 20 <Y>  y: 32 bytes
/// ```
fn es256_key(cose: &[u8]) -> Result<[u8; PUBLIC_KEY_BYTES], Refused> {
    const HEAD: [u8; 10] = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    const MID: [u8; 3] = [0x22, 0x58, 0x20];
    if cose.len() != 77 || cose[..10] != HEAD || cose[42..45] != MID {
        return Err(Refused::UnsupportedKey);
    }
    let mut key = [0u8; PUBLIC_KEY_BYTES];
    key[0] = 0x04;
    key[1..33].copy_from_slice(&cose[10..42]);
    key[33..].copy_from_slice(&cose[45..]);
    Ok(key)
}

/// 7.2.19–20: the signature covers authenticatorData ‖ SHA-256(clientDataJSON).
fn check_signature(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    client_data_json: &[u8],
    auth_data: &[u8],
    signature: &[u8],
) -> Result<(), Refused> {
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&sha256(client_data_json));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&signed, signature)
        .map_err(|_| Refused::BadSignature)
}

/// Verify the answer to `navigator.credentials.get()` against a registered
/// passkey. Returns the passkey's new signature counter, to be stored.
pub fn verify_assertion(
    site: &Site,
    challenge: &[u8],
    public_key: &[u8; PUBLIC_KEY_BYTES],
    stored_sign_count: u32,
    client_data_json: &[u8],
    auth_data: &[u8],
    signature: &[u8],
) -> Result<u32, Refused> {
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(Refused::TooLarge);
    }
    check_client_data(client_data_json, "webauthn.get", challenge, site)?;
    let (_, sign_count, rest) = check_auth_data(auth_data, site)?;
    // A signature carries the header only: no new key, no extensions.
    if !rest.is_empty() {
        return Err(Refused::AuthData);
    }
    check_signature(public_key, client_data_json, auth_data, signature)?;
    // 7.2.21: a counter that is in use must only go up. Synced passkeys
    // report 0 every time, which says nothing either way.
    if (sign_count != 0 || stored_sign_count != 0) && sign_count <= stored_sign_count {
        return Err(Refused::CounterWentBack);
    }
    Ok(sign_count)
}

/// Checks against responses from a real hardware authenticator, taken from
/// the test suite of py_webauthn 2.2.0 (Duo Labs, BSD licence). They guard
/// against this crate and its own test authenticator sharing a misreading of
/// the specification.
#[cfg(test)]
mod real_device {
    use super::*;

    fn decode(s: &str) -> Vec<u8> {
        base64url_decode(s).expect("valid base64url")
    }

    fn site() -> Site {
        Site {
            origin: "http://localhost:5000".into(),
            rp_id: "localhost".into(),
        }
    }

    #[test]
    fn decode_is_the_strict_inverse_of_base64url() {
        for len in 0..40u8 {
            let bytes: Vec<u8> = (0..len).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
            assert_eq!(base64url_decode(&base64url(&bytes)), Some(bytes));
        }
        // Padding, the standard alphabet, stray characters, impossible
        // lengths and non-zero leftover bits are all refused.
        for bad in [
            "Zg==", "Zm9v+", "Zm9v/", "Zm 9v", "Z", "Zm9vY", "Zh", "Zm9", "Zg\n",
        ] {
            assert_eq!(base64url_decode(bad), None, "{bad:?}");
        }
        assert_eq!(base64url_decode("Zm8"), Some(b"fo".to_vec()));
    }

    /// `test_verifies_none_attestation_response`: flags UP|UV|AT, counter 23.
    #[test]
    fn registration_from_a_real_authenticator_verifies() {
        let auth_data = decode(concat!(
            "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf",
            "7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRF",
            "u_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
        ));
        let client = decode(concat!(
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5",
            "VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8v",
            "bG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        ));
        let challenge = decode(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw",
        );
        let reg = verify_registration(&site(), &challenge, &client, &auth_data).unwrap();
        assert_eq!(
            reg.credential_id,
            decode(
                "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w"
            )
        );
        assert_eq!(reg.sign_count, 23);
        assert!(!reg.backup_eligible);
        assert_eq!(reg.public_key[0], 0x04);

        let other = Site {
            origin: "http://localhost:5000".into(),
            rp_id: "example.com".into(),
        };
        assert_eq!(
            verify_registration(&other, &challenge, &client, &auth_data),
            Err(Refused::WrongRpId)
        );
    }

    /// `test_verify_authentication_response_with_EC2_public_key`: counter 78,
    /// made with user presence only.
    #[test]
    fn signature_from_a_real_authenticator_verifies() {
        let cose = decode(concat!(
            "pQECAyYgASFYIIeDTe-gN8A-zQclHoRnGFWN8ehM1b7yAsa8I8KIvmplIlgg4nFGT5px8o6gpPZZhO01wdy9crDSA_Ngtkx0",
            "vGpvPHI",
        ));
        let auth_data = decode("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAATg");
        let client = decode(concat!(
            "eyJjaGFsbGVuZ2UiOiJ4aTMwR1BHQUZZUnhWRHBZMXNNMTBEYUx6VlFHNjZudi1fN1JVYXpIMHZJMll2RzhMWWdERW52TjVm",
            "WlpOVnV2RUR1TWk5dGUzVkxxYjQyTjBma0xHQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hB",
            "LTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ",
        ));
        let signature = decode(
            "MEUCIGisVZOBapCWbnJJvjelIzwpixxIwkjCCb5aCHafQu68AiEA88v-2pJNNApPFwAKFiNuf82-2hBxYW5kGwVweeoxCwo",
        );
        let challenge = decode(
            "xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA",
        );

        // The key decoding and the signature check, on real bytes.
        let key = es256_key(&cose).unwrap();
        assert_eq!(
            check_signature(&key, &client, &auth_data, &signature),
            Ok(())
        );
        let mut tampered = auth_data.clone();
        tampered[36] ^= 1;
        assert_eq!(
            check_signature(&key, &client, &tampered, &signature),
            Err(Refused::BadSignature)
        );

        // Client data and the header pass every check up to user verification,
        // which this authenticator did not do, so Key-Box refuses it.
        assert_eq!(
            check_client_data(&client, "webauthn.get", &challenge, &site()),
            Ok(())
        );
        assert_eq!(
            verify_assertion(
                &site(),
                &challenge,
                &key,
                77,
                &client,
                &auth_data,
                &signature
            ),
            Err(Refused::UserNotVerified)
        );
    }
}
