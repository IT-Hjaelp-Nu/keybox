//! Everything Key-Box knows, behind one lock, and everything the approval
//! page can do to it.
//!
//! The rules live in `keybox-core`. This module connects them to passkeys:
//! nothing here moves a request forward except a verified passkey signature
//! over a challenge that Key-Box itself derived from that request.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use keybox_core::engine::{Engine, EventKind};
use keybox_core::ident::{CredentialId, RequestId};
use keybox_core::policy::Level;
use keybox_log::{AuditLog, Record};
use keybox_webauthn::{
    Refused, Site, approval_challenge, base64url, verify_assertion, verify_registration,
};
use serde_json::{Value, json};

use crate::passkeys::{Passkey, Passkeys, use_token};
use crate::policy::{Files, Proposal};
use crate::push::{MAX_SUBSCRIPTIONS, Notice, PUSH_ORIGINS, Subscription, Vapid};
use crate::store::Store;
use crate::{Error, random};
use keybox_log::Field;
use keybox_policy::{Loaded, load_files};

pub const LOG_FILE: &str = "audit.log";
/// Agents are refused until this many passkeys exist: one to use, one spare.
pub const DEFAULT_MIN_PASSKEYS: usize = 2;
pub const MAX_PASSKEYS: usize = 8;
/// How long Christian has to complete one passkey prompt.
pub const CHALLENGE_TTL_SECS: u64 = 120;
const MAX_CHALLENGES: usize = 16;
/// One user: every passkey belongs to Christian.
const USER_HANDLE: &[u8] = b"keybox-christian";

/// A refusal for the approval page: HTTP status and a fixed word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deny(pub u16, pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Purpose {
    Register {
        name: CredentialId,
    },
    Approve {
        request: RequestId,
        binding: Vec<u8>,
    },
    Stop,
    Resume,
    /// Put the proposed policy with this hash into force.
    Policy {
        hash: [u8; 32],
    },
    /// Send notifications to this browser.
    Notify {
        subscription: Subscription,
    },
}

impl Purpose {
    fn word(&self) -> &'static str {
        match self {
            Purpose::Register { .. } => "register",
            Purpose::Approve { .. } => "approve",
            Purpose::Stop => "stop",
            Purpose::Resume => "resume",
            Purpose::Policy { .. } => "policy",
            Purpose::Notify { .. } => "notify",
        }
    }
}

struct Challenge {
    purpose: Purpose,
    bytes: [u8; 32],
    expires_at: u64,
    /// Order of issue. Several can share one second, so time alone does not order them.
    issued: u64,
}

pub struct Core {
    pub engine: Engine,
    pub log: AuditLog,
    pub passkeys: Passkeys,
    pub site: Site,
    pub store: Store,
    /// The policy in force: the one Christian last approved.
    pub loaded: Loaded,
    /// Where proposed policy files are read from. `None`: nothing can be proposed.
    pub policy_dir: Option<PathBuf>,
    dir: PathBuf,
    challenges: BTreeMap<String, Challenge>,
    challenges_issued: u64,
    /// Set when the audit log could not be written. Key-Box then stops.
    pub log_failed: bool,
    /// How many passkeys must exist before agents are served.
    pub min_passkeys: usize,
    /// The push service notifications may be posted to, by its origins.
    pub push_origins: Vec<String>,
    /// Where notices go to be sent. `None`: Key-Box sends no notifications.
    pub notices: Option<tokio::sync::mpsc::Sender<Notice>>,
}

impl Core {
    /// Open Key-Box' state. It starts on the policy that was last approved;
    /// before the first approval that is the empty policy, which allows nothing.
    pub fn open(dir: &Path, site: Site) -> Result<Self, Error> {
        let store = Store::open(dir)?;
        let (stopped, saved) = store.load()?;
        let loaded = load_files(&store.policy_files()?)?;
        let mut core = Self {
            // What was open before the restart is checked against the policy
            // as it is now; an emergency stop stays on.
            engine: Engine::restore(loaded.policy.clone(), stopped, saved, crate::now()),
            log: AuditLog::open(&dir.join(LOG_FILE))?,
            passkeys: Passkeys::load(dir)?,
            site,
            store,
            loaded,
            policy_dir: None,
            dir: dir.to_owned(),
            challenges: BTreeMap::new(),
            challenges_issued: 0,
            min_passkeys: DEFAULT_MIN_PASSKEYS,
            log_failed: false,
            push_origins: PUSH_ORIGINS.map(String::from).to_vec(),
            notices: None,
        };
        core.commit()?;
        Ok(core)
    }

    /// Put a policy into force. The caller has checked that Christian
    /// approved exactly these files. Open requests the new policy does not
    /// allow, or places on another level, are revoked.
    pub fn install_policy(&mut self, now: u64, files: Files) -> Result<(), Error> {
        let loaded = load_files(&files)?;
        self.commit()?;
        self.store.set_policy_files(&files)?;
        let (stopped, saved) = self.engine.snapshot();
        self.engine = Engine::restore(loaded.policy.clone(), stopped, saved, now);
        self.loaded = loaded;
        self.commit()?;
        Ok(())
    }

    /// The hash of the policy in force.
    pub fn policy_hash(&self) -> [u8; 32] {
        crate::policy::hash(&self.store.policy_files().unwrap_or_default())
    }

    /// The files on disk, compared with the policy in force.
    pub fn proposal(&self) -> Proposal {
        let Some(dir) = &self.policy_dir else {
            return Proposal::Same;
        };
        let Ok(files) = crate::policy::read_dir(dir) else {
            return Proposal::Unreadable;
        };
        let hash = crate::policy::hash(&files);
        if hash == self.policy_hash() {
            return Proposal::Same;
        }
        match load_files(&files) {
            Ok(new) => {
                let changes = crate::policy::diff(&self.loaded, &new);
                Proposal::Pending {
                    hash,
                    files,
                    changes,
                }
            }
            Err(e) => Proposal::Invalid(e.to_string()),
        }
    }

    /// Save the engine's state, then write what it did to the log. Nobody is
    /// answered before both are on disk. State goes first: a request that was
    /// handed out must never look un-fetched after a crash.
    pub fn commit(&mut self) -> Result<(), keybox_log::LogError> {
        let (stopped, saved) = self.engine.snapshot();
        self.store
            .save(stopped, &saved)
            .map_err(|_| keybox_log::LogError::Io(std::io::ErrorKind::Other))?;
        let mut waiting = Vec::new();
        for event in self.engine.drain_events() {
            // Levels 2 and 3 wait for Christian. Level 1 does not.
            if let (EventKind::Requested { spec, level, .. }, Some(id), Some(agent)) =
                (&event.kind, &event.request, &event.agent)
                && *level != Level::One
            {
                waiting.push(Notice::request(id, agent, *level, spec));
            }
            self.log.append(&event.into())?;
        }
        // Told only once the request is saved and in the log.
        for notice in waiting {
            self.notify(notice);
        }
        Ok(())
    }

    // ------------------------------------------------------- notifications

    /// Queue a notification. If the queue is full it is dropped: the page
    /// still shows everything, and nothing waits on a notification.
    pub fn notify(&self, notice: Notice) {
        if let Some(notices) = &self.notices {
            let _ = notices.try_send(notice);
        }
    }

    /// The key notifications are signed with. Made on first use.
    fn vapid(&mut self) -> Option<Vapid> {
        if let Some(key) = self.store.meta("push-key").ok()? {
            return Vapid::from_text(&key);
        }
        let key = Vapid::generate()?;
        self.store.set_meta("push-key", &key.to_text()).ok()?;
        Some(key)
    }

    /// The public half of that key, for the browser to subscribe with.
    pub fn push_public_key(&mut self) -> Option<String> {
        self.vapid()?.public()
    }

    fn subscriptions(&self) -> Vec<Subscription> {
        let text = self.store.meta("push-subscriptions").ok().flatten();
        crate::push::from_text(&self.push_origins, &text.unwrap_or_default())
    }

    fn set_subscriptions(&mut self, list: &[Subscription]) -> Result<(), Deny> {
        self.store
            .set_meta("push-subscriptions", &crate::push::to_text(list))
            .map_err(|_| Deny(500, "storage"))
    }

    /// The subscribed devices by their marks. The page uses them to tell
    /// whether the browser it runs in is one of them.
    pub fn push_marks(&self) -> Vec<String> {
        let hex = |mark: [u8; 32]| mark[..8].iter().map(|b| format!("{b:02x}")).collect();
        self.subscriptions().iter().map(|s| hex(s.mark())).collect()
    }

    /// The devices to send to, each with the proof of sender made out to
    /// its push service.
    pub fn push_targets(&mut self, now: u64) -> Vec<(Subscription, Option<String>)> {
        let devices = self.subscriptions();
        if devices.is_empty() {
            return Vec::new();
        }
        let key = self.vapid();
        let subject = self.site.origin.clone();
        devices
            .into_iter()
            .map(|device| {
                let proof = key
                    .as_ref()
                    .and_then(|key| key.authorization(now, device.origin(), &subject));
                (device, proof)
            })
            .collect()
    }

    /// Record how a round of notifications went, and forget the devices the
    /// push service says are gone.
    pub fn push_done(
        &mut self,
        now: u64,
        about: &'static str,
        sent: u64,
        failed: u64,
        gone: &[Subscription],
    ) {
        let record = Record::new(now, "notified")
            .word("about", about)
            .with("devices", sent)
            .with("failed", failed);
        let _ = self.note(record);
        if gone.is_empty() {
            return;
        }
        let mut list = self.subscriptions();
        list.retain(|s| !gone.contains(s));
        let _ = self.set_subscriptions(&list);
        for device in gone {
            let record = Record::new(now, "notify-off")
                .with("device", Field::hex(&device.mark()))
                .word("by", "push-service");
            let _ = self.note(record);
        }
    }

    /// Stop sending to one browser. Needs no passkey, but needs the
    /// browser's own address, which only that browser has.
    pub fn notify_off(&mut self, now: u64, endpoint: &str) -> Result<Value, Deny> {
        let mut list = self.subscriptions();
        let Some(at) = list.iter().position(|s| s.is(endpoint)) else {
            return Err(Deny(404, "unknown-subscription"));
        };
        let device = list.remove(at);
        self.set_subscriptions(&list)?;
        let record = Record::new(now, "notify-off")
            .with("device", Field::hex(&device.mark()))
            .word("by", "device");
        self.note(record)?;
        Ok(json!({ "ok": true, "done": "notify-off" }))
    }

    /// Agents are served only once the spare passkey exists too.
    pub fn is_set_up(&self) -> bool {
        self.passkeys.list().len() >= self.min_passkeys
    }

    fn note(&mut self, record: Record) -> Result<(), Deny> {
        self.log.append(&record).map_err(|_| {
            self.log_failed = true;
            Deny(500, "log")
        })
    }

    /// Write what the engine did to the log.
    fn flush(&mut self) -> Result<(), Deny> {
        self.commit().map_err(|_| {
            self.log_failed = true;
            Deny(500, "log")
        })
    }

    fn credential_ids(&self) -> Vec<String> {
        self.passkeys
            .list()
            .iter()
            .map(|p| base64url(&p.credential_id))
            .collect()
    }

    fn issue(&mut self, now: u64, purpose: Purpose, bytes: [u8; 32]) -> Result<Value, Deny> {
        self.challenges.retain(|_, c| c.expires_at > now);
        // Anyone who can reach the page can ask for challenges. When full,
        // the oldest gives way, so the newest prompt always works.
        while self.challenges.len() >= MAX_CHALLENGES {
            let oldest = self.challenges.iter().min_by_key(|(_, c)| c.issued);
            let Some(id) = oldest.map(|(id, _)| id.clone()) else {
                break;
            };
            self.challenges.remove(&id);
        }
        let id = base64url(&random::<16>().map_err(|_| Deny(500, "random"))?);
        self.challenges_issued += 1;
        let challenge = Challenge {
            purpose,
            bytes,
            expires_at: now + CHALLENGE_TTL_SECS,
            issued: self.challenges_issued,
        };
        self.challenges.insert(id.clone(), challenge);
        Ok(json!({
            "ok": true,
            "challenge_id": id,
            "challenge": base64url(&bytes),
            "rp_id": self.site.rp_id,
            "user_id": base64url(USER_HANDLE),
            "credentials": self.credential_ids(),
        }))
    }

    /// A challenge can be answered once, right or wrong.
    fn take(&mut self, now: u64, id: &str) -> Result<Challenge, Deny> {
        match self.challenges.remove(id) {
            Some(c) if c.expires_at > now => Ok(c),
            _ => Err(Deny(403, "challenge")),
        }
    }

    // ------------------------------------------------------- registration

    /// Begin registering a passkey called `name`. This always needs the
    /// one-time token from the server's console. A passkey cannot add another
    /// passkey: if it could, whoever holds one stolen device could make
    /// themselves the "second, different passkey" that level 3 asks for, and
    /// would keep access after the device was blocked.
    pub fn register_start(
        &mut self,
        now: u64,
        name: &str,
        token: Option<&str>,
    ) -> Result<Value, Deny> {
        let name = CredentialId::new(name).map_err(|_| Deny(400, "invalid-name"))?;
        if self.passkeys.has_name(&name) {
            return Err(Deny(409, "name-taken"));
        }
        if self.passkeys.list().len() >= MAX_PASSKEYS {
            return Err(Deny(409, "too-many-passkeys"));
        }
        if !token.is_some_and(|t| use_token(&self.dir, t, now)) {
            self.note(Record::new(now, "register-refused").word("why", "not-authorized"))?;
            return Err(Deny(403, "not-authorized"));
        }
        self.note(
            Record::new(now, "register-started")
                .with("credential", &name)
                .word("by", "console-token"),
        )?;
        let bytes = random::<32>().map_err(|_| Deny(500, "random"))?;
        self.issue(now, Purpose::Register { name }, bytes)
    }

    pub fn register_finish(
        &mut self,
        now: u64,
        challenge_id: &str,
        client_data: &[u8],
        auth_data: &[u8],
    ) -> Result<Value, Deny> {
        let challenge = self.take(now, challenge_id)?;
        let Purpose::Register { name } = challenge.purpose else {
            return Err(Deny(403, "challenge"));
        };
        let registered =
            match verify_registration(&self.site, &challenge.bytes, client_data, auth_data) {
                Ok(r) => r,
                Err(why) => {
                    let record = Record::new(now, "register-refused").with("credential", &name);
                    self.note(record.word("why", refused_word(why)))?;
                    return Err(Deny(403, refused_word(why)));
                }
            };
        if self
            .passkeys
            .by_credential(&registered.credential_id)
            .is_some()
        {
            return Err(Deny(409, "already-registered"));
        }
        // Checked again here: two registrations begun at the same moment
        // must not both end up under one name.
        if self.passkeys.has_name(&name) {
            return Err(Deny(409, "name-taken"));
        }
        let synced = registered.backup_eligible;
        self.passkeys
            .add(Passkey {
                name: name.clone(),
                credential_id: registered.credential_id,
                public_key: registered.public_key,
                sign_count: registered.sign_count,
                synced,
            })
            .map_err(|_| Deny(500, "storage"))?;
        let record = Record::new(now, "passkey-added").with("credential", &name);
        self.note(record.word("synced", if synced { "yes" } else { "no" }))?;
        Ok(json!({ "ok": true, "name": name.as_str(), "synced": synced }))
    }

    // ---------------------------------------------------------- signatures

    /// Begin a passkey prompt. For an approval, the challenge is derived here
    /// from Key-Box' own copy of the request, never from anything the browser sends.
    pub fn assert_start(
        &mut self,
        now: u64,
        purpose: &str,
        request: Option<&str>,
        subscription: Option<Subscription>,
    ) -> Result<Value, Deny> {
        if self.passkeys.list().is_empty() {
            return Err(Deny(409, "no-passkeys"));
        }
        let nonce = random::<32>().map_err(|_| Deny(500, "random"))?;
        let (purpose, bytes) = match purpose {
            "approve" => {
                let id = request.and_then(|r| RequestId::new(r).ok());
                let id = id.ok_or(Deny(400, "invalid-request"))?;
                if self.engine.is_stopped() {
                    return Err(Deny(409, "stopped"));
                }
                let waiting = self.engine.awaiting_approval(now);
                self.flush()?;
                if !waiting.iter().any(|w| w.id == id) {
                    return Err(Deny(404, "unknown-request"));
                }
                let binding = self
                    .engine
                    .binding(&id)
                    .ok_or(Deny(404, "unknown-request"))?
                    .to_vec();
                let bytes = approval_challenge(&nonce, &binding);
                (
                    Purpose::Approve {
                        request: id,
                        binding,
                    },
                    bytes,
                )
            }
            "stop" => (
                Purpose::Stop,
                approval_challenge(&nonce, b"keybox:emergency-stop"),
            ),
            "resume" if self.engine.is_stopped() => (
                Purpose::Resume,
                approval_challenge(&nonce, b"keybox:resume"),
            ),
            "resume" => return Err(Deny(409, "not-stopped")),
            // The signature covers the hash of the files as they are right
            // now. If they change before it is used, it approves nothing.
            "policy" => match self.proposal() {
                Proposal::Pending { hash, .. } => {
                    let mut bound = b"keybox:policy:".to_vec();
                    bound.extend_from_slice(&hash);
                    (Purpose::Policy { hash }, approval_challenge(&nonce, &bound))
                }
                _ => return Err(Deny(409, "no-policy-to-approve")),
            },
            // The signature covers this browser's address and keys, so it
            // cannot be used to subscribe another one.
            "notify" => {
                let subscription = subscription.ok_or(Deny(400, "malformed"))?;
                let mut bound = b"keybox:notify:".to_vec();
                bound.extend_from_slice(&subscription.mark());
                (
                    Purpose::Notify { subscription },
                    approval_challenge(&nonce, &bound),
                )
            }
            _ => return Err(Deny(400, "invalid-purpose")),
        };
        self.issue(now, purpose, bytes)
    }

    /// Verify the passkey's answer and, only then, do what it was for.
    pub fn assert_finish(
        &mut self,
        now: u64,
        challenge_id: &str,
        credential_id: &[u8],
        client_data: &[u8],
        auth_data: &[u8],
        signature: &[u8],
    ) -> Result<Value, Deny> {
        let challenge = self.take(now, challenge_id)?;
        if matches!(challenge.purpose, Purpose::Register { .. }) {
            return Err(Deny(403, "challenge"));
        }
        let what = challenge.purpose.word();
        let Some(passkey) = self.passkeys.by_credential(credential_id).cloned() else {
            self.note(
                Record::new(now, "passkey-refused")
                    .word("for", what)
                    .word("why", "unknown-passkey"),
            )?;
            return Err(Deny(403, "unknown-passkey"));
        };
        let verified = verify_assertion(
            &self.site,
            &challenge.bytes,
            &passkey.public_key,
            passkey.sign_count,
            client_data,
            auth_data,
            signature,
        );
        let sign_count = match verified {
            Ok(count) => count,
            Err(why) => {
                let record = Record::new(now, "passkey-refused").with("credential", &passkey.name);
                self.note(record.word("for", what).word("why", refused_word(why)))?;
                return Err(Deny(403, refused_word(why)));
            }
        };
        self.passkeys
            .set_sign_count(&passkey.name, sign_count)
            .map_err(|_| Deny(500, "storage"))?;
        self.note(
            Record::new(now, "passkey-verified")
                .with("credential", &passkey.name)
                .word("for", what),
        )?;

        match challenge.purpose {
            Purpose::Approve { request, binding } => {
                let result = self.engine.approve(now, &request, &binding, &passkey.name);
                self.flush()?;
                result.map_err(|refusal| Deny(409, refusal.code()))?;
            }
            Purpose::Stop => {
                // The delivered accesses still alive are returned for the
                // issuers to revoke; there are no issuers yet.
                let _live = self.engine.emergency_stop(now);
                self.flush()?;
            }
            Purpose::Resume => {
                self.engine.resume(now);
                self.flush()?;
            }
            Purpose::Policy { hash } => {
                let files = match self.proposal() {
                    Proposal::Pending {
                        hash: now_hash,
                        files,
                        ..
                    } if now_hash == hash => files,
                    _ => return Err(Deny(409, "policy-changed")),
                };
                let count = files.len() as u64;
                if self.install_policy(now, files).is_err() {
                    self.log_failed = true;
                    return Err(Deny(500, "storage"));
                }
                let record = Record::new(now, "policy-approved")
                    .with("credential", &passkey.name)
                    .with("hash", Field::hex(&hash))
                    .with("files", count);
                self.note(record)?;
            }
            Purpose::Notify { subscription } => {
                let mut list = self.subscriptions();
                list.retain(|s| *s != subscription);
                // The oldest gives way to the newest.
                while list.len() >= MAX_SUBSCRIPTIONS {
                    list.remove(0);
                }
                list.push(subscription.clone());
                self.set_subscriptions(&list)?;
                let record = Record::new(now, "notify-on")
                    .with("credential", &passkey.name)
                    .with("device", Field::hex(&subscription.mark()));
                self.note(record)?;
                self.notify(Notice::enabled());
            }
            Purpose::Register { .. } => {}
        }
        Ok(json!({ "ok": true, "done": what }))
    }

    /// The GitHub Apps in the policy in force.
    pub fn github_apps(&self) -> Vec<crate::issuer::App> {
        self.loaded
            .github_apps()
            .map(|(name, id)| (name.clone(), id.to_owned()))
            .collect()
    }

    /// GitHub installations an emergency stop suspended and resume has not
    /// yet lifted.
    pub fn github_suspended(&self) -> Vec<u64> {
        let list = self
            .store
            .meta("github-suspended")
            .ok()
            .flatten()
            .unwrap_or_default();
        list.split(',').filter_map(|id| id.parse().ok()).collect()
    }

    /// True if GitHub could not be shut off, or switched back on, completely.
    pub fn github_incomplete(&self) -> bool {
        self.store
            .meta("github-incomplete")
            .ok()
            .flatten()
            .as_deref()
            == Some("yes")
    }

    fn set_github(&mut self, ids: &[u64], incomplete: bool) {
        let list: Vec<String> = ids.iter().map(u64::to_string).collect();
        let saved = self
            .store
            .set_meta("github-suspended", &list.join(","))
            .is_ok()
            && self
                .store
                .set_meta("github-incomplete", if incomplete { "yes" } else { "no" })
                .is_ok();
        if !saved {
            self.log_failed = true;
        }
    }

    /// Record what an emergency stop did at GitHub.
    pub fn github_stopped(&mut self, now: u64, suspended: &[u64], failed: bool) {
        let mut all = self.github_suspended();
        all.extend(
            suspended
                .iter()
                .filter(|id| !all.contains(id))
                .copied()
                .collect::<Vec<_>>(),
        );
        self.set_github(&all, failed);
        let record = Record::new(now, "github-suspended")
            .with("installations", suspended.len() as u64)
            .word("complete", if failed { "no" } else { "yes" });
        let _ = self.note(record);
    }

    /// Record what switching back on did at GitHub. `left` could not be lifted.
    pub fn github_resumed(&mut self, now: u64, lifted: usize, left: &[u64]) {
        self.set_github(left, !left.is_empty());
        let record = Record::new(now, "github-resumed")
            .with("installations", lifted as u64)
            .word("complete", if left.is_empty() { "yes" } else { "no" });
        let _ = self.note(record);
    }

    /// Reject a request or cancel a level-3 delay. Needs no passkey: it can
    /// only close things.
    pub fn cancel(&mut self, now: u64, request: &str) -> Result<Value, Deny> {
        let id = RequestId::new(request).map_err(|_| Deny(400, "invalid-request"))?;
        let result = self.engine.cancel(now, &id);
        self.flush()?;
        result.map_err(|refusal| Deny(409, refusal.code()))?;
        Ok(json!({ "ok": true, "done": "cancel" }))
    }
}

fn refused_word(why: Refused) -> &'static str {
    match why {
        Refused::TooLarge => "too-large",
        Refused::ClientData => "client-data",
        Refused::WrongType => "wrong-type",
        Refused::WrongChallenge => "wrong-challenge",
        Refused::WrongOrigin => "wrong-origin",
        Refused::CrossOrigin => "cross-origin",
        Refused::AuthData => "auth-data",
        Refused::WrongRpId => "wrong-rp-id",
        Refused::UserNotPresent => "user-not-present",
        Refused::UserNotVerified => "user-not-verified",
        Refused::UnsupportedKey => "unsupported-key",
        Refused::BadSignature => "bad-signature",
        Refused::CounterWentBack => "counter-went-back",
    }
}
