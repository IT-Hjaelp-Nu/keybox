//! Turns a released request into the access itself.
//!
//! This is the only place that touches both a fixed key and the network. It
//! runs after the engine has released the request and the release is in the
//! audit log, and outside the lock, so a slow issuer cannot stall approvals.
//!
//! The issuer holds no policy of its own. Each call is told what the policy
//! in force says, read under the lock at the moment the request was released,
//! so a newly approved policy takes effect on the very next request.

use std::sync::Arc;

use keybox_core::engine::Delivery;
use keybox_core::ident::{AgentId, RequestId, SecretName, SshPublicKey};
use keybox_policy::Method;
use zeroize::Zeroizing;

use crate::github::Github;
use crate::secrets::{Secret, Secrets};

pub struct Issuer {
    pub secrets: Arc<dyn Secrets>,
    pub github: Github,
}

/// What is handed to the agent. No `Debug`; the line is wiped on drop.
pub struct Issued {
    /// A fixed word for the log.
    pub kind: &'static str,
    /// The fields of the answer after `"ok":true`, as JSON members.
    pub members: Zeroizing<String>,
}

/// A released request, with what the policy in force says about issuing it.
pub struct Released<'a> {
    pub id: &'a RequestId,
    pub agent: &'a AgentId,
    pub delivery: &'a Delivery,
    pub method: Option<&'a Method>,
    /// The client id of the method's GitHub App.
    pub client_id: Option<&'a str>,
    /// The key to certify, for an SSH certificate.
    pub public_key: Option<&'a SshPublicKey>,
}

/// A GitHub App from the policy: the name of its key, and its public client id.
pub type App = (SecretName, String);

impl Issuer {
    /// Looking a secret up may run a program and wait for it, so it is done
    /// off the thread that serves everyone else.
    async fn key(&self, name: &SecretName) -> Option<Secret> {
        let (secrets, name) = (self.secrets.clone(), name.clone());
        tokio::task::spawn_blocking(move || secrets.get(&name))
            .await
            .ok()?
            .ok()
    }

    /// Issue the access for a released request the way its method says, or
    /// say in one fixed word why not.
    pub async fn issue(&self, now: u64, released: &Released<'_>) -> Result<Issued, &'static str> {
        let spec = &released.delivery.spec;
        match released.method {
            Some(Method::GithubApp(app)) => {
                let client_id = released.client_id.ok_or("issuer-unavailable")?;
                let key = self.key(&app.app).await.ok_or("secret-unavailable")?;
                let repo = spec.target.as_str();
                let token = self
                    .github
                    .issue(now, client_id, &key, repo, &app.permissions)
                    .await
                    .map_err(|e| e.word())?;
                // Token, timestamp and target have each been checked to hold
                // no quote or backslash, so they can be placed in JSON as they are.
                let members = format!(
                    r#""kind":"github-token","repository":"{repo}","expires_at":"{}","token":"{}""#,
                    token.expires_at,
                    token.token.as_str()
                );
                Ok(Issued {
                    kind: "github-token",
                    members: Zeroizing::new(members),
                })
            }
            Some(Method::SshCert(rule)) => {
                // Checked before the CA key is fetched at all.
                let public_key = released.public_key.ok_or("ssh-public-key-required")?;
                let ca = self.key(&rule.ca).await.ok_or("secret-unavailable")?;
                let key_id = format!("keybox:{}:{}", released.agent, released.id);
                let nonce = crate::random::<32>().map_err(|_| "ssh-sign-failed")?;
                let serial =
                    u64::from_be_bytes(crate::random::<8>().map_err(|_| "ssh-sign-failed")?);
                let certificate = crate::ssh::certify(
                    now,
                    &ca,
                    public_key,
                    rule,
                    spec.pin.as_ref(),
                    &key_id,
                    nonce,
                    serial,
                )?;
                // Host, user name and certificate line hold no quote or backslash.
                let members = format!(
                    r#""kind":"ssh-certificate","host":"{}","principal":"{}","valid_before":{},"certificate":"{}""#,
                    spec.target, rule.principal, certificate.valid_before, certificate.line
                );
                Ok(Issued {
                    kind: "ssh-certificate",
                    members: Zeroizing::new(members),
                })
            }
            None => Err("issuer-unavailable"),
        }
    }

    /// Emergency stop: suspend every installation of every App in `apps`
    /// that is not suspended already. Returns the ones this call suspended,
    /// and whether anything could not be done.
    pub async fn suspend_all(&self, now: u64, apps: &[App]) -> (Vec<u64>, bool) {
        let (mut done, mut failed) = (Vec::new(), false);
        for (name, client_id) in apps {
            let Some(key) = self.key(name).await else {
                failed = true;
                continue;
            };
            let Ok(installations) = self.github.installations(now, client_id, &key).await else {
                failed = true;
                continue;
            };
            for (id, already) in installations {
                if already {
                    continue;
                }
                match self
                    .github
                    .set_suspended(now, client_id, &key, id, true)
                    .await
                {
                    Ok(()) => done.push(id),
                    Err(_) => failed = true,
                }
            }
        }
        (done, failed)
    }

    /// Lift the suspensions an earlier stop made. Returns the ones that
    /// could not be lifted; those stay recorded for another try.
    pub async fn resume(&self, now: u64, apps: &[App], suspended: &[u64]) -> Vec<u64> {
        let mut left: Vec<u64> = suspended.to_vec();
        for (name, client_id) in apps {
            let Some(key) = self.key(name).await else {
                continue;
            };
            let Ok(installations) = self.github.installations(now, client_id, &key).await else {
                continue;
            };
            for (id, is_suspended) in installations {
                if !left.contains(&id) {
                    continue;
                }
                if !is_suspended
                    || self
                        .github
                        .set_suspended(now, client_id, &key, id, false)
                        .await
                        .is_ok()
                {
                    left.retain(|x| *x != id);
                }
            }
        }
        left
    }
}
