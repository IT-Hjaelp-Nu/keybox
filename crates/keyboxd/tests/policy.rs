//! Policy files are a proposal. Only a passkey signature over exactly those
//! files puts them into force.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use common::{Authenticator, Box, POLICY, RESTART, TIMEOUT, block_on, id_of, site};
use keyboxd::core::Core;
use serde_json::{Value, json};

/// A Key-Box with passkeys but no approved policy, reading proposals from a
/// directory the test writes to.
struct Rig {
    b: Box,
    dir: PathBuf,
    agents: SocketAddr,
    web: SocketAddr,
    phone: Authenticator,
}

/// The test policy as one file for the App and one for the customer.
fn split() -> (String, String) {
    let at = POLICY.find("[customers").unwrap();
    (POLICY[..at].to_owned(), POLICY[at..].to_owned())
}

async fn rig(name: &str) -> Rig {
    let b = Box::new(name);
    let dir = b.dir.join("policy.d");
    std::fs::create_dir_all(&dir).unwrap();
    let (apps, acme) = split();
    std::fs::write(dir.join("apps.toml"), apps).unwrap();
    std::fs::write(dir.join("acme.toml"), acme).unwrap();
    // Things that are not policy files and must be left alone.
    std::fs::write(dir.join("README.md"), "noter").unwrap();
    std::fs::create_dir_all(dir.join(".git")).unwrap();

    let mut core = Core::open(&b.dir, site()).unwrap();
    core.policy_dir = Some(dir.clone());
    let core = Arc::new(Mutex::new(core));
    let agents = b.start_agents(core.clone(), TIMEOUT).await;
    let web = b.start_web(core, TIMEOUT).await;
    let phone = Authenticator::new("phone");
    b.enroll(web, "phone", &phone).await;
    b.enroll(web, "spare", &Authenticator::new("spare")).await;
    Rig {
        b,
        dir,
        agents,
        web,
        phone,
    }
}

impl Rig {
    async fn ask(&self, line: &str) -> String {
        self.b.call(self.agents, "hermes", line).await.unwrap()
    }

    async fn page(&self) -> String {
        self.b.get(self.web, "/").await.2
    }

    async fn approve_policy(&self) -> (u16, Value) {
        self.b.sign(self.web, &self.phone, "policy", None).await
    }

    fn edit(&self, file: &str, from: &str, to: &str) {
        let path = self.dir.join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(from), "test bug: {from}");
        std::fs::write(path, text.replacen(from, to, 1)).unwrap();
    }
}

fn error(reply: &(u16, Value)) -> (u16, &str) {
    (reply.0, reply.1["error"].as_str().unwrap_or(""))
}

const UNKNOWN: &str = r#"{"error":"policy:unknown-customer","ok":false}"#;

#[test]
fn nothing_is_allowed_until_the_first_policy_is_approved() {
    block_on(async {
        let r = rig("pol-first").await;
        // The files are there, but nobody has approved them.
        assert_eq!(r.ask(RESTART).await, UNKNOWN);
        let page = r.page().await;
        assert!(page.contains("I kraft: 0 handlinger"), "{page}");
        assert!(page.contains("Ny policy venter på dig"));
        for shown in [
            "Ny: GitHub App github-app",
            "Ny: acme · web01 · restart",
            "niveau 2",
            "agenter: hermes",
            "web01.acme.example",
            "/usr/bin/systemctl restart nginx",
        ] {
            assert!(page.contains(shown), "missing {shown} in page");
        }

        assert_eq!(r.approve_policy().await.0, 200);
        assert!(r.ask(RESTART).await.contains(r#""state":"pending""#));
        let page = r.page().await;
        assert!(
            page.contains("I kraft: 4 handlinger") && !page.contains("Ny policy venter"),
            "{page}"
        );
        // Nothing left to approve.
        assert_eq!(
            error(&r.approve_policy().await),
            (409, "no-policy-to-approve")
        );

        let log = r.b.log_text();
        assert!(
            log.contains(r#""kind":"policy-approved""#)
                && log.contains(r#""credential":"phone""#)
                && log.contains(r#""files":2"#),
            "{log}"
        );
    });
}

#[test]
fn a_changed_file_changes_nothing_until_it_is_approved() {
    block_on(async {
        let r = rig("pol-change").await;
        assert_eq!(r.approve_policy().await.0, 200);

        // Someone lowers "restart" to level 1: no passkey needed any more.
        r.edit(
            "acme.toml",
            "[customers.acme.systems.web01.actions.restart]\nlevel = 2",
            "[customers.acme.systems.web01.actions.restart]\nlevel = 1",
        );
        let page = r.page().await;
        assert!(page.contains("Ændres: acme · web01 · restart"), "{page}");
        assert!(page.contains("Kræver mindre godkendelse end før."));
        assert!(page.contains("Før:</span> niveau 2") && page.contains("Nu:</span> niveau 1"));
        // Still level 2 in force: the request waits for a passkey.
        assert!(r.ask(RESTART).await.contains(r#""state":"pending""#));

        assert_eq!(r.approve_policy().await.0, 200);
        assert!(r.ask(RESTART).await.contains(r#""state":"ready""#));
    });
}

#[test]
fn an_approval_covers_the_files_as_they_were_when_it_was_asked_for() {
    block_on(async {
        let r = rig("pol-race").await;
        let start = json!({"purpose": "policy", "request": null});
        let (_, begun) = r.b.post(r.web, "/api/assert/start", &start).await;
        // The files change between the prompt and the signature.
        r.edit("acme.toml", "level = 2", "level = 1");
        let mut finish = r.phone.get(begun["challenge"].as_str().unwrap());
        finish["challenge_id"] = begun["challenge_id"].clone();
        assert_eq!(
            error(&r.b.post(r.web, "/api/assert/finish", &finish).await),
            (409, "policy-changed")
        );
        // Nothing came into force: neither the old proposal nor the new one.
        assert_eq!(r.ask(RESTART).await, UNKNOWN);
        assert!(r.page().await.contains("I kraft: 0 handlinger"));
    });
}

#[test]
fn a_broken_file_cannot_be_approved_and_the_old_policy_stays() {
    block_on(async {
        let r = rig("pol-broken").await;
        assert_eq!(r.approve_policy().await.0, 200);
        r.edit("acme.toml", "level = 2", "level = 9");
        let page = r.page().await;
        assert!(
            page.contains("Policy-filerne har en fejl")
                && page.contains("acme.toml")
                && page.contains("level"),
            "{page}"
        );
        assert!(!page.contains("Godkend ny policy med passkey"));
        assert_eq!(
            error(&r.approve_policy().await),
            (409, "no-policy-to-approve")
        );
        assert!(r.ask(RESTART).await.contains(r#""state":"pending""#));

        // The same customer in a second file is refused the same way.
        r.edit("acme.toml", "level = 9", "level = 2");
        std::fs::write(r.dir.join("ekstra.toml"), "[customers.acme.systems.x.actions.y]\nlevel = 1\nagents = [\"hermes\"]\ntargets = [\"z\"]\nmethod = { github_app = { app = \"github-app\", permissions = { contents = \"read\" } } }\n").unwrap();
        assert!(r.page().await.contains("more than one file"));
        assert_eq!(
            error(&r.approve_policy().await),
            (409, "no-policy-to-approve")
        );
    });
}

#[test]
fn removing_a_customer_revokes_what_was_open_for_them() {
    block_on(async {
        let r = rig("pol-remove").await;
        assert_eq!(r.approve_policy().await.0, 200);
        let id = id_of(&r.ask(RESTART).await);
        assert_eq!(r.b.sign(r.web, &r.phone, "approve", Some(&id)).await.0, 200);

        std::fs::remove_file(r.dir.join("acme.toml")).unwrap();
        // The app file stays, but nothing uses the app any more.
        let page = r.page().await;
        assert!(page.contains("Fjernes: acme · web01 · restart"), "{page}");
        // Until approved, the approved request can still be fetched... so approve first.
        assert_eq!(r.approve_policy().await.0, 200);
        let fetch = format!(r#"{{"op":"fetch","id":"{id}"}}"#);
        assert_eq!(r.ask(&fetch).await, r#"{"error":"closed","ok":false}"#);
        assert_eq!(r.ask(RESTART).await, UNKNOWN);
        assert!(r.b.log_text().contains(r#""kind":"revoked""#));
    });
}

#[test]
fn only_a_registered_passkey_can_approve_a_policy() {
    block_on(async {
        let r = rig("pol-passkey").await;
        let stranger = Authenticator::new("stranger");
        assert_eq!(
            error(&r.b.sign(r.web, &stranger, "policy", None).await),
            (403, "unknown-passkey")
        );
        // The phone's credential id with another key behind it.
        let mut forged = Authenticator::new("x");
        forged.id = r.phone.id.clone();
        assert_eq!(r.b.sign(r.web, &forged, "policy", None).await.0, 403);
        // There is no way in without a signature.
        for path in ["/api/policy", "/api/policy/approve", "/api/reload"] {
            assert_eq!(
                error(&r.b.post(r.web, path, &json!({})).await),
                (404, "not-found")
            );
        }
        assert_eq!(r.ask(RESTART).await, UNKNOWN);
    });
}

#[test]
fn text_from_a_policy_file_is_shown_as_text() {
    block_on(async {
        let r = rig("pol-html").await;
        r.edit(
            "acme.toml",
            "/usr/bin/systemctl restart nginx",
            "/bin/x <script>alert(1)</script> <b>&amp;",
        );
        let page = r.page().await;
        assert!(
            page.contains("&lt;script&gt;alert(1)&lt;/script&gt; &lt;b&gt;&amp;amp;"),
            "{page}"
        );
        assert_eq!(page.matches("<script").count(), 1);
    });
}

#[test]
fn the_approved_policy_survives_a_restart_and_the_files_are_not_trusted_then_either() {
    let b = Box::new("pol-restart");
    let dir = b.dir.join("policy.d");
    std::fs::create_dir_all(&dir).unwrap();
    let files = vec![("test.toml".to_owned(), POLICY.to_owned())];
    let mut core = Core::open(&b.dir, site()).unwrap();
    core.install_policy(keyboxd::now(), files).unwrap();
    let approved = core.policy_hash();
    drop(core);

    // While Key-Box is down, a much wider policy is put in the directory.
    std::fs::write(
        dir.join("alt.toml"),
        POLICY
            .replace("level = 2", "level = 1")
            .replace("level = 3", "level = 1"),
    )
    .unwrap();
    let mut core = Core::open(&b.dir, site()).unwrap();
    core.policy_dir = Some(dir);
    assert_eq!(core.policy_hash(), approved);
    assert_eq!(core.loaded.actions().count(), 4);
    let levels: Vec<_> = core
        .loaded
        .actions()
        .map(|(.., rule, _)| rule.level)
        .collect();
    assert!(levels.contains(&keybox_core::policy::Level::Three));
    assert!(matches!(
        core.proposal(),
        keyboxd::policy::Proposal::Pending { .. }
    ));
}

#[test]
fn a_change_of_comments_only_still_needs_approval_and_says_so() {
    block_on(async {
        let r = rig("pol-comment").await;
        assert_eq!(r.approve_policy().await.0, 200);
        let path = r.dir.join("acme.toml");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("# en kommentar\n{text}")).unwrap();
        let page = r.page().await;
        assert!(
            page.contains("Ny policy venter på dig") && page.contains("0 ændringer"),
            "{page}"
        );
        assert!(page.contains("ingen regler er"));
        assert_eq!(r.approve_policy().await.0, 200);
        assert!(!r.page().await.contains("Ny policy venter"));
    });
}
