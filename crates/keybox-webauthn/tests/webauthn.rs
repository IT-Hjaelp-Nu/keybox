//! Passkey verification, tested against a software authenticator built here
//! from the specification: every field is checked for itself.

use keybox_webauthn::{
    Refused, Registered, Site, approval_challenge, base64url, verify_assertion, verify_registration,
};
use proptest::prelude::*;
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

fn site() -> Site {
    Site {
        origin: "https://keybox.example.ts.net".into(),
        rp_id: "keybox.example.ts.net".into(),
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}

/// A passkey: a P-256 key bound to one RP ID.
struct Passkey {
    key: EcdsaKeyPair,
    id: Vec<u8>,
    rp_id: String,
}

impl Passkey {
    fn new(rp_id: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            key,
            id: b"credential-id-0001".to_vec(),
            rp_id: rp_id.to_owned(),
        }
    }

    fn public(&self) -> [u8; 65] {
        self.key.public_key().as_ref().try_into().unwrap()
    }

    fn header(&self, flags: u8, count: u32) -> Vec<u8> {
        let mut data = sha256(self.rp_id.as_bytes());
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        data
    }

    fn cose_key(&self) -> Vec<u8> {
        let public = self.public();
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(&public[1..33]);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&public[33..]);
        cose
    }

    /// authenticatorData for `create()`.
    fn attested(&self, flags: u8, count: u32) -> Vec<u8> {
        let mut data = self.header(flags, count);
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.id);
        data.extend_from_slice(&self.cose_key());
        data
    }

    fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let mut signed = auth_data.to_vec();
        signed.extend_from_slice(&sha256(client_data));
        self.key
            .sign(&SystemRandom::new(), &signed)
            .unwrap()
            .as_ref()
            .to_vec()
    }
}

/// clientDataJSON as a browser writes it.
fn client_data(kind: &str, challenge: &[u8; 32], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        base64url(challenge)
    )
    .into_bytes()
}

const CHALLENGE: [u8; 32] = [7; 32];

/// A complete, valid approval signature and everything needed to check it.
struct Signed {
    public: [u8; 65],
    client: Vec<u8>,
    auth: Vec<u8>,
    sig: Vec<u8>,
}

fn signed(count: u32) -> Signed {
    let passkey = Passkey::new(&site().rp_id);
    let client = client_data("webauthn.get", &CHALLENGE, &site().origin);
    let auth = passkey.header(UP | UV, count);
    let sig = passkey.sign(&auth, &client);
    Signed {
        public: passkey.public(),
        client,
        auth,
        sig,
    }
}

fn check(s: &Signed, stored: u32) -> Result<u32, Refused> {
    verify_assertion(
        &site(),
        &CHALLENGE,
        &s.public,
        stored,
        &s.client,
        &s.auth,
        &s.sig,
    )
}

// --------------------------------------------------------------- encoding

#[test]
fn base64url_matches_rfc_4648() {
    for (input, want) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64url(input.as_bytes()), want);
    }
    assert_eq!(base64url(&[0xfb, 0xff, 0xfe]), "-__-");
}

#[test]
fn approval_challenge_depends_on_nonce_and_request() {
    let base = approval_challenge(&[1; 32], b"request-a");
    assert_ne!(base, approval_challenge(&[2; 32], b"request-a"));
    assert_ne!(base, approval_challenge(&[1; 32], b"request-b"));
    assert_eq!(base, approval_challenge(&[1; 32], b"request-a"));
}

// -------------------------------------------------------------- assertion

#[test]
fn valid_signature_is_accepted() {
    assert_eq!(check(&signed(0), 0), Ok(0));
    assert_eq!(check(&signed(5), 4), Ok(5));
}

#[test]
fn signature_for_another_challenge_is_refused() {
    // The heart of "one approval = one request": the same passkey, the same
    // site, a perfectly good signature, but over a different request.
    let passkey = Passkey::new(&site().rp_id);
    let other = approval_challenge(&[9; 32], b"deploy to customer B");
    let client = client_data("webauthn.get", &other, &site().origin);
    let auth = passkey.header(UP | UV, 0);
    let sig = passkey.sign(&auth, &client);
    let wanted = approval_challenge(&[9; 32], b"deploy to customer A");
    let out = verify_assertion(&site(), &wanted, &passkey.public(), 0, &client, &auth, &sig);
    assert_eq!(out, Err(Refused::WrongChallenge));
}

#[test]
fn signature_made_on_a_phishing_site_is_refused() {
    // A page on another origin asks the browser to sign Key-Box' challenge.
    // The browser writes the true origin into clientDataJSON...
    let passkey = Passkey::new(&site().rp_id);
    for origin in [
        "https://keybox.example.ts.net.evil.example",
        "https://evil.example",
        "http://keybox.example.ts.net",
        "https://keybox.example.ts.net:8443",
        "https://KEYBOX.example.ts.net",
        "https://keybox.example.ts.net/",
    ] {
        let client = client_data("webauthn.get", &CHALLENGE, origin);
        let auth = passkey.header(UP | UV, 0);
        let sig = passkey.sign(&auth, &client);
        let out = verify_assertion(
            &site(),
            &CHALLENGE,
            &passkey.public(),
            0,
            &client,
            &auth,
            &sig,
        );
        assert_eq!(out, Err(Refused::WrongOrigin), "{origin}");
    }
    // ...and a passkey made for another site hashes another RP ID.
    let foreign = Passkey::new("evil.example");
    let client = client_data("webauthn.get", &CHALLENGE, &site().origin);
    let auth = foreign.header(UP | UV, 0);
    let sig = foreign.sign(&auth, &client);
    let out = verify_assertion(
        &site(),
        &CHALLENGE,
        &foreign.public(),
        0,
        &client,
        &auth,
        &sig,
    );
    assert_eq!(out, Err(Refused::WrongRpId));
}

#[test]
fn user_verification_is_required() {
    let passkey = Passkey::new(&site().rp_id);
    let client = client_data("webauthn.get", &CHALLENGE, &site().origin);
    for (flags, want) in [
        (UP, Refused::UserNotVerified),
        (UV, Refused::UserNotPresent),
        (0, Refused::UserNotPresent),
        (UP | UV | ED, Refused::AuthData),
    ] {
        let auth = passkey.header(flags, 0);
        let sig = passkey.sign(&auth, &client);
        let out = verify_assertion(
            &site(),
            &CHALLENGE,
            &passkey.public(),
            0,
            &client,
            &auth,
            &sig,
        );
        assert_eq!(out, Err(want), "flags {flags:#04x}");
    }
}

#[test]
fn a_registration_response_is_not_an_approval() {
    let passkey = Passkey::new(&site().rp_id);
    let client = client_data("webauthn.create", &CHALLENGE, &site().origin);
    let auth = passkey.header(UP | UV, 0);
    let sig = passkey.sign(&auth, &client);
    let out = verify_assertion(
        &site(),
        &CHALLENGE,
        &passkey.public(),
        0,
        &client,
        &auth,
        &sig,
    );
    assert_eq!(out, Err(Refused::WrongType));
}

#[test]
fn cross_origin_frames_are_refused() {
    let passkey = Passkey::new(&site().rp_id);
    let client = String::from_utf8(client_data("webauthn.get", &CHALLENGE, &site().origin))
        .unwrap()
        .replace(r#""crossOrigin":false"#, r#""crossOrigin":true"#)
        .into_bytes();
    let auth = passkey.header(UP | UV, 0);
    let sig = passkey.sign(&auth, &client);
    let out = verify_assertion(
        &site(),
        &CHALLENGE,
        &passkey.public(),
        0,
        &client,
        &auth,
        &sig,
    );
    assert_eq!(out, Err(Refused::CrossOrigin));
}

#[test]
fn signature_from_another_key_is_refused() {
    let mut s = signed(0);
    s.public = Passkey::new(&site().rp_id).public();
    assert_eq!(check(&s, 0), Err(Refused::BadSignature));
}

#[test]
fn changing_any_signed_byte_is_refused() {
    let s = signed(1);
    for i in 0..s.auth.len() {
        let mut t = Signed {
            public: s.public,
            client: s.client.clone(),
            auth: s.auth.clone(),
            sig: s.sig.clone(),
        };
        t.auth[i] ^= 0x10;
        assert!(check(&t, 0).is_err(), "authenticatorData byte {i}");
    }
    for i in 0..s.client.len() {
        let mut t = Signed {
            public: s.public,
            client: s.client.clone(),
            auth: s.auth.clone(),
            sig: s.sig.clone(),
        };
        t.client[i] ^= 0x01;
        assert!(check(&t, 0).is_err(), "clientDataJSON byte {i}");
    }
    for i in 0..s.sig.len() {
        let mut t = Signed {
            public: s.public,
            client: s.client.clone(),
            auth: s.auth.clone(),
            sig: s.sig.clone(),
        };
        t.sig[i] ^= 0x01;
        assert!(check(&t, 0).is_err(), "signature byte {i}");
    }
    assert_eq!(check(&s, 0), Ok(1));
}

#[test]
fn a_counter_that_goes_back_is_refused() {
    assert_eq!(check(&signed(5), 5), Err(Refused::CounterWentBack));
    assert_eq!(check(&signed(5), 9), Err(Refused::CounterWentBack));
    // A passkey that used to count and now says 0 is suspicious too.
    assert_eq!(check(&signed(0), 3), Err(Refused::CounterWentBack));
}

#[test]
fn truncated_extended_and_oversized_input_is_refused() {
    let s = signed(0);
    let with = |client: &[u8], auth: &[u8], sig: &[u8]| {
        verify_assertion(&site(), &CHALLENGE, &s.public, 0, client, auth, sig)
    };
    assert_eq!(
        with(&s.client, &s.auth[..36], &s.sig),
        Err(Refused::AuthData)
    );
    assert_eq!(with(&s.client, &[], &s.sig), Err(Refused::AuthData));
    let mut longer = s.auth.clone();
    longer.push(0);
    assert_eq!(with(&s.client, &longer, &s.sig), Err(Refused::AuthData));
    assert_eq!(
        with(&s.client, &vec![0; 2049], &s.sig),
        Err(Refused::TooLarge)
    );
    assert_eq!(
        with(&vec![b' '; 4097], &s.auth, &s.sig),
        Err(Refused::TooLarge)
    );
    assert_eq!(with(&s.client, &s.auth, &[0; 129]), Err(Refused::TooLarge));
    assert_eq!(with(&s.client, &s.auth, &[]), Err(Refused::BadSignature));
    assert_eq!(with(b"not json", &s.auth, &s.sig), Err(Refused::ClientData));
    assert_eq!(with(b"{}", &s.auth, &s.sig), Err(Refused::ClientData));
}

#[test]
fn unknown_client_data_fields_from_newer_browsers_are_tolerated() {
    let passkey = Passkey::new(&site().rp_id);
    let client = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template"}}"#,
        base64url(&CHALLENGE),
        site().origin
    )
    .into_bytes();
    let auth = passkey.header(UP | UV, 0);
    let sig = passkey.sign(&auth, &client);
    let out = verify_assertion(
        &site(),
        &CHALLENGE,
        &passkey.public(),
        0,
        &client,
        &auth,
        &sig,
    );
    assert_eq!(out, Ok(0));
}

// ----------------------------------------------------------- registration

fn register(passkey: &Passkey, flags: u8) -> Result<Registered, Refused> {
    let client = client_data("webauthn.create", &CHALLENGE, &site().origin);
    verify_registration(&site(), &CHALLENGE, &client, &passkey.attested(flags, 0))
}

#[test]
fn valid_registration_yields_the_key_that_later_signs() {
    let passkey = Passkey::new(&site().rp_id);
    let reg = register(&passkey, UP | UV | AT | BE).unwrap();
    assert_eq!(reg.credential_id, passkey.id);
    assert_eq!(reg.public_key, passkey.public());
    assert!(reg.backup_eligible);
    assert!(!register(&passkey, UP | UV | AT).unwrap().backup_eligible);

    let client = client_data("webauthn.get", &CHALLENGE, &site().origin);
    let auth = passkey.header(UP | UV, 0);
    let sig = passkey.sign(&auth, &client);
    let out = verify_assertion(
        &site(),
        &CHALLENGE,
        &reg.public_key,
        reg.sign_count,
        &client,
        &auth,
        &sig,
    );
    assert_eq!(out, Ok(0));
}

#[test]
fn registration_checks_site_challenge_type_and_user_verification() {
    let passkey = Passkey::new(&site().rp_id);
    let auth = passkey.attested(UP | UV | AT, 0);
    let reg = |client: &[u8], auth: &[u8]| verify_registration(&site(), &CHALLENGE, client, auth);

    let wrong_origin = client_data("webauthn.create", &CHALLENGE, "https://evil.example");
    assert_eq!(reg(&wrong_origin, &auth), Err(Refused::WrongOrigin));
    let wrong_challenge = client_data("webauthn.create", &[8; 32], &site().origin);
    assert_eq!(reg(&wrong_challenge, &auth), Err(Refused::WrongChallenge));
    let wrong_type = client_data("webauthn.get", &CHALLENGE, &site().origin);
    assert_eq!(reg(&wrong_type, &auth), Err(Refused::WrongType));

    assert_eq!(
        register(&passkey, UP | AT).unwrap_err(),
        Refused::UserNotVerified
    );
    assert_eq!(
        register(&passkey, UV | AT).unwrap_err(),
        Refused::UserNotPresent
    );
    assert_eq!(register(&passkey, UP | UV).unwrap_err(), Refused::AuthData);
    assert_eq!(
        register(&passkey, UP | UV | AT | ED).unwrap_err(),
        Refused::AuthData
    );
    assert_eq!(
        register(&Passkey::new("evil.example"), UP | UV | AT).unwrap_err(),
        Refused::WrongRpId
    );
}

#[test]
fn registration_accepts_only_the_exact_es256_key_encoding() {
    let passkey = Passkey::new(&site().rp_id);
    let client = client_data("webauthn.create", &CHALLENGE, &site().origin);
    let good = passkey.attested(UP | UV | AT, 0);
    let key_at = good.len() - 77;
    let reg = |auth: &[u8]| verify_registration(&site(), &CHALLENGE, &client, auth);

    // Each header byte of the key matters: other algorithm, curve or shape.
    for offset in (0..10).chain(42..45) {
        let mut bad = good.clone();
        bad[key_at + offset] ^= 0x01;
        assert_eq!(reg(&bad), Err(Refused::UnsupportedKey), "key byte {offset}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(reg(&trailing), Err(Refused::UnsupportedKey));
    assert_eq!(reg(&good[..good.len() - 1]), Err(Refused::UnsupportedKey));
    assert_eq!(reg(&good[..key_at]), Err(Refused::UnsupportedKey));
    assert_eq!(reg(&good[..50]), Err(Refused::AuthData));

    // A credential id length that points past the end, or is zero.
    let mut long_id = good.clone();
    long_id[53] = 0xff;
    long_id[54] = 0xff;
    assert_eq!(reg(&long_id), Err(Refused::AuthData));
    let mut no_id = good.clone();
    no_id[53] = 0;
    no_id[54] = 0;
    assert_eq!(reg(&no_id), Err(Refused::AuthData));
    assert!(reg(&good).is_ok());
}

// ------------------------------------------------------------------- fuzz

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn arbitrary_input_never_panics_and_never_verifies(
        client in proptest::collection::vec(any::<u8>(), 0..300),
        auth in proptest::collection::vec(any::<u8>(), 0..300),
        sig in proptest::collection::vec(any::<u8>(), 0..100),
        key in proptest::collection::vec(any::<u8>(), 65),
    ) {
        let key: [u8; 65] = key.try_into().unwrap();
        prop_assert!(verify_assertion(&site(), &CHALLENGE, &key, 0, &client, &auth, &sig).is_err());
        prop_assert!(verify_registration(&site(), &CHALLENGE, &client, &auth).is_err());
    }

    /// Well-formed client data and header, arbitrary tail and signature.
    #[test]
    fn arbitrary_tail_and_signature_never_verify(
        tail in proptest::collection::vec(any::<u8>(), 0..200),
        sig in proptest::collection::vec(any::<u8>(), 0..100),
        flags in any::<u8>(),
        kind in "webauthn\\.(get|create)",
    ) {
        let passkey = Passkey::new(&site().rp_id);
        let client = client_data(&kind, &CHALLENGE, &site().origin);
        let mut auth = passkey.header(flags, 0);
        auth.extend_from_slice(&tail);
        let out = verify_assertion(&site(), &CHALLENGE, &passkey.public(), 0, &client, &auth, &sig);
        prop_assert!(out.is_err());
        if let Ok(reg) = verify_registration(&site(), &CHALLENGE, &client, &auth) {
            // Only reachable with the right flags and an exact key layout.
            prop_assert!(flags & (UP | UV | AT) == (UP | UV | AT) && flags & ED == 0);
            prop_assert_eq!(reg.public_key[0], 0x04);
        }
    }

    #[test]
    fn base64url_uses_only_its_alphabet(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let s = base64url(&bytes);
        prop_assert_eq!(s.len(), (bytes.len() * 4).div_ceil(3));
        prop_assert!(s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    }
}
