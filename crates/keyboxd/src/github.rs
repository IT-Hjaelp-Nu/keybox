//! Short-lived GitHub tokens.
//!
//! The GitHub App's private key is a fixed key and never leaves Key-Box. With
//! it Key-Box signs a ten-minute proof of being the App, and trades that for
//! an installation token limited to one repository and the permissions the
//! policy names. GitHub fixes the token's life at one hour.
//!
//! What GitHub returns is checked against what was asked for. A token that
//! reaches further than the approved request is revoked, not handed out.

use std::collections::BTreeMap;
use std::fmt;

use hyper::Method;
use keybox_policy::Access;
use keybox_webauthn::base64url;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::https::HttpsClient;
use crate::secrets::Secret;

/// How long the App's proof of identity lives. GitHub allows at most ten minutes.
const JWT_LIFETIME_SECS: u64 = 300;
/// Allowance for Key-Box' clock being ahead of GitHub's.
const JWT_BACKDATE_SECS: u64 = 60;

/// Why no token was issued. Fixed words only: nothing from GitHub's answer
/// and nothing about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// The App's private key is not a usable RSA key.
    BadKey,
    /// GitHub could not be reached, or did not answer in time.
    Unreachable,
    /// The App is not installed on that repository.
    NotInstalled,
    /// GitHub said no.
    Refused,
    /// GitHub's answer was not what the API promises.
    BadAnswer,
    /// The token GitHub made covered more than was asked for. It was revoked.
    TooBroad,
}

impl IssueError {
    pub fn word(self) -> &'static str {
        match self {
            IssueError::BadKey => "github-bad-key",
            IssueError::Unreachable => "github-unreachable",
            IssueError::NotInstalled => "github-not-installed",
            IssueError::Refused => "github-refused",
            IssueError::BadAnswer => "github-bad-answer",
            IssueError::TooBroad => "github-token-too-broad",
        }
    }
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// An installation token. No `Debug`; the value is wiped on drop.
pub struct Token {
    pub token: Zeroizing<String>,
    /// As GitHub states it, e.g. `2026-10-11T03:00:00Z`. Checked to be exactly that shape.
    pub expires_at: String,
}

#[derive(Clone)]
pub struct Github {
    client: HttpsClient,
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: String,
    expires_at: String,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
    #[serde(default)]
    repository_selection: String,
    #[serde(default)]
    repositories: Vec<Repository>,
}

#[derive(Deserialize)]
struct Repository {
    full_name: String,
}

impl Github {
    pub fn new(client: HttpsClient) -> Self {
        Self::at(client, "api.github.com", 443)
    }

    /// Another host, for tests.
    pub fn at(client: HttpsClient, host: &str, port: u16) -> Self {
        Self {
            client,
            host: host.to_owned(),
            port,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), IssueError> {
        let authorization = Zeroizing::new(format!("Bearer {bearer}"));
        let headers = [
            ("authorization", authorization.as_str()),
            ("accept", "application/vnd.github+json"),
            ("x-github-api-version", "2022-11-28"),
            ("user-agent", "keybox"),
            ("content-type", "application/json"),
        ];
        self.client
            .send(&self.host, self.port, method, path, &headers, body)
            .await
            .map_err(|_| IssueError::Unreachable)
    }

    /// A token for `repo` (`owner/name`) with exactly `permissions`.
    pub async fn issue(
        &self,
        now: u64,
        client_id: &str,
        app_key: &Secret,
        repo: &str,
        permissions: &BTreeMap<String, Access>,
    ) -> Result<Token, IssueError> {
        let jwt = app_jwt(now, client_id, app_key)?;
        let (owner, name) = repo.split_once('/').ok_or(IssueError::BadAnswer)?;

        // Which installation of the App covers this repository?
        let path = format!("/repos/{owner}/{name}/installation");
        let (status, body) = self.call(Method::GET, &path, &jwt, Vec::new()).await?;
        let installation: Installation = match status {
            200 => serde_json::from_slice(&body).map_err(|_| IssueError::BadAnswer)?,
            404 => return Err(IssueError::NotInstalled),
            _ => return Err(IssueError::Refused),
        };

        let wanted: BTreeMap<&str, &str> = permissions
            .iter()
            .map(|(k, v)| (k.as_str(), access_word(*v)))
            .collect();
        let request = json!({ "repositories": [name], "permissions": wanted }).to_string();
        let path = format!("/app/installations/{}/access_tokens", installation.id);
        let (status, body) = self
            .call(Method::POST, &path, &jwt, request.into_bytes())
            .await?;
        let body = Zeroizing::new(body);
        if status != 201 {
            return Err(IssueError::Refused);
        }
        let answer: TokenAnswer =
            serde_json::from_slice(&body).map_err(|_| IssueError::BadAnswer)?;
        let token = Zeroizing::new(answer.token);

        let well_formed = is_token(&token) && is_timestamp(&answer.expires_at);
        let narrow = answer.repository_selection == "selected"
            && answer.repositories.len() == 1
            && answer.repositories[0].full_name.eq_ignore_ascii_case(repo)
            && answer
                .permissions
                .iter()
                .all(|(k, v)| within(&wanted, k, v));
        if !well_formed || !narrow {
            // Best effort: the token exists at GitHub whether or not we keep it.
            if is_token(&token) {
                let _ = self
                    .call(Method::DELETE, "/installation/token", &token, Vec::new())
                    .await;
            }
            return Err(if narrow {
                IssueError::BadAnswer
            } else {
                IssueError::TooBroad
            });
        }
        Ok(Token {
            token,
            expires_at: answer.expires_at,
        })
    }
}

#[derive(Deserialize)]
struct InstallationState {
    id: u64,
    suspended_at: Option<String>,
}

impl Github {
    /// The App's installations: id, and whether it is suspended already.
    pub async fn installations(
        &self,
        now: u64,
        client_id: &str,
        app_key: &Secret,
    ) -> Result<Vec<(u64, bool)>, IssueError> {
        let jwt = app_jwt(now, client_id, app_key)?;
        let path = "/app/installations?per_page=100";
        let (status, body) = self.call(Method::GET, path, &jwt, Vec::new()).await?;
        if status != 200 {
            return Err(IssueError::Refused);
        }
        let list: Vec<InstallationState> =
            serde_json::from_slice(&body).map_err(|_| IssueError::BadAnswer)?;
        Ok(list
            .into_iter()
            .map(|i| (i.id, i.suspended_at.is_some()))
            .collect())
    }

    /// Suspend an installation, which makes every token issued for it stop
    /// working at once, or lift the suspension again.
    pub async fn set_suspended(
        &self,
        now: u64,
        client_id: &str,
        app_key: &Secret,
        installation: u64,
        suspended: bool,
    ) -> Result<(), IssueError> {
        let jwt = app_jwt(now, client_id, app_key)?;
        let method = if suspended {
            Method::PUT
        } else {
            Method::DELETE
        };
        let path = format!("/app/installations/{installation}/suspended");
        match self.call(method, &path, &jwt, Vec::new()).await?.0 {
            204 => Ok(()),
            _ => Err(IssueError::Refused),
        }
    }
}

fn access_word(access: Access) -> &'static str {
    match access {
        Access::Read => "read",
        Access::Write => "write",
    }
}

/// Is a permission GitHub reports within what was asked? GitHub always adds
/// read access to repository metadata.
fn within(wanted: &BTreeMap<&str, &str>, permission: &str, level: &str) -> bool {
    match wanted.get(permission) {
        Some(&"write") => level == "write" || level == "read",
        Some(&"read") => level == "read",
        _ => permission == "metadata" && level == "read",
    }
}

/// Printable ASCII without spaces or quotes, of a plausible length.
fn is_token(token: &str) -> bool {
    (20..=512).contains(&token.len())
        && token
            .bytes()
            .all(|c| c.is_ascii_graphic() && c != b'"' && c != b'\\')
}

/// Exactly `YYYY-MM-DDTHH:MM:SSZ`.
fn is_timestamp(text: &str) -> bool {
    let shape = b"dddd-dd-ddTdd:dd:ddZ";
    text.len() == shape.len()
        && text.bytes().zip(shape).all(|(c, s)| {
            if *s == b'd' {
                c.is_ascii_digit()
            } else {
                c == *s
            }
        })
}

/// The App's signed proof of identity (RFC 7519, RS256).
fn app_jwt(now: u64, client_id: &str, app_key: &Secret) -> Result<Zeroizing<String>, IssueError> {
    let der = PrivateKeyDer::from_pem_slice(app_key.expose()).map_err(|_| IssueError::BadKey)?;
    let key = match &der {
        PrivateKeyDer::Pkcs1(k) => RsaKeyPair::from_der(k.secret_pkcs1_der()),
        PrivateKeyDer::Pkcs8(k) => RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()),
        _ => return Err(IssueError::BadKey),
    }
    .map_err(|_| IssueError::BadKey)?;

    let header = base64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = json!({
        "iss": client_id,
        "iat": now.saturating_sub(JWT_BACKDATE_SECS),
        "exp": now + JWT_LIFETIME_SECS,
    });
    let signed = format!("{header}.{}", base64url(claims.to_string().as_bytes()));
    let mut signature = vec![0u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signed.as_bytes(),
        &mut signature,
    )
    .map_err(|_| IssueError::BadKey)?;
    Ok(Zeroizing::new(format!(
        "{signed}.{}",
        base64url(&signature)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_permissions_must_be_within_the_request() {
        let wanted = BTreeMap::from([("contents", "read"), ("pull_requests", "write")]);
        assert!(within(&wanted, "contents", "read"));
        assert!(!within(&wanted, "contents", "write"));
        assert!(within(&wanted, "pull_requests", "write"));
        assert!(within(&wanted, "pull_requests", "read"));
        assert!(within(&wanted, "metadata", "read"));
        assert!(!within(&wanted, "metadata", "write"));
        assert!(!within(&wanted, "administration", "read"));
        assert!(!within(&wanted, "contents", "admin"));
    }

    #[test]
    fn token_and_timestamp_shapes() {
        assert!(is_token("ghs_16C7e42F292c6912E7710c838347Ae178B4a"));
        for bad in [
            "",
            "short",
            "ghs_with space_0000000000000",
            "ghs_\"quote\"0000000000000000",
            &"x".repeat(513),
        ] {
            assert!(!is_token(bad), "{bad:?}");
        }
        assert!(is_timestamp("2026-10-11T03:00:00Z"));
        for bad in [
            "",
            "2026-10-11 03:00:00Z",
            "2026-10-11T03:00:00+02:00",
            "2026-10-11T03:00:00Z\n",
            "tomorrow",
        ] {
            assert!(!is_timestamp(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_key_that_is_not_rsa_pem_is_refused_without_detail() {
        for bad in [
            "",
            "not a key",
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
        ] {
            let out = app_jwt(
                1_800_000_000,
                "Iv23li",
                &Secret::new(bad.as_bytes().to_vec()),
            );
            assert_eq!(out.err(), Some(IssueError::BadKey));
        }
    }
}
