//! Core security tests. These define the rules; the engine is built to pass them.

use keybox_core::engine::{
    APPROVAL_WINDOW_SECS, Engine, EventKind, FETCH_WINDOW_SECS, KEEP_CLOSED_SECS,
    LEVEL3_DELAY_SECS, MAX_OPEN_PER_AGENT, Refusal, State,
};
use keybox_core::ident::{
    ActionId, AgentId, CredentialId, CustomerId, Pin, PinKind, RequestId, SystemId, Target,
};
use keybox_core::policy::{ActionRule, Deny, Level, Policy};
use keybox_core::request::{Reason, RequestSpec};

const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";
const SHA_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
const T0: u64 = 1_800_000_000;

fn agent(s: &str) -> AgentId {
    AgentId::new(s).unwrap()
}

fn cred(s: &str) -> CredentialId {
    CredentialId::new(s).unwrap()
}

fn rid(n: u8) -> RequestId {
    RequestId::new(&format!("{n:032x}")).unwrap()
}

fn spec(customer: &str, system: &str, action: &str, target: &str, pin: Option<Pin>) -> RequestSpec {
    RequestSpec {
        customer: CustomerId::new(customer).unwrap(),
        system: SystemId::new(system).unwrap(),
        action: ActionId::new(action).unwrap(),
        target: Target::new(target).unwrap(),
        pin,
    }
}

fn rule(level: Level, agents: &[&str], targets: &[&str], pin: Option<PinKind>) -> ActionRule {
    ActionRule {
        level,
        agents: agents.iter().map(|a| agent(a)).collect(),
        targets: targets.iter().map(|t| Target::new(t).unwrap()).collect(),
        pin,
        ttl_secs: 1800,
    }
}

fn policy() -> Policy {
    let mut p = Policy::default();
    let mut add = |c: &str, s: &str, a: &str, r: ActionRule| {
        p.insert(
            CustomerId::new(c).unwrap(),
            SystemId::new(s).unwrap(),
            ActionId::new(a).unwrap(),
            r,
        );
    };
    add(
        "acme",
        "github",
        "read-code",
        rule(Level::One, &["hermes", "coder"], &["org/acme-web"], None),
    );
    add(
        "acme",
        "web01",
        "deploy",
        rule(
            Level::Two,
            &["hermes"],
            &["web01.acme.example"],
            Some(PinKind::Commit),
        ),
    );
    add(
        "acme",
        "web01",
        "restart",
        rule(Level::Two, &["hermes"], &["web01.acme.example"], None),
    );
    add(
        "acme",
        "m365",
        "edit-users",
        rule(Level::Three, &["hermes"], &["acme.onmicrosoft.com"], None),
    );
    add(
        "bravo",
        "web01",
        "restart",
        rule(Level::Two, &["hermes"], &["web01.bravo.example"], None),
    );
    p
}

fn engine() -> Engine {
    Engine::new(policy())
}

fn reason() -> Reason {
    Reason::new("Kunden bad om det").unwrap()
}

fn deploy(sha: &str) -> RequestSpec {
    spec(
        "acme",
        "web01",
        "deploy",
        "web01.acme.example",
        Some(Pin::commit(sha).unwrap()),
    )
}

fn restart_spec() -> RequestSpec {
    spec("acme", "web01", "restart", "web01.acme.example", None)
}

fn m365() -> RequestSpec {
    spec("acme", "m365", "edit-users", "acme.onmicrosoft.com", None)
}

/// Submit and return the binding Christian would sign.
fn submit(e: &mut Engine, n: u8, s: RequestSpec) -> Vec<u8> {
    e.submit(T0, &agent("hermes"), rid(n), s, reason()).unwrap();
    e.binding(&rid(n)).unwrap().to_vec()
}

// ---------------------------------------------------------------- policy

#[test]
fn policy_denies_everything_not_listed() {
    let mut e = engine();
    let h = agent("hermes");
    let cases = [
        (
            spec("nobody", "web01", "restart", "web01.acme.example", None),
            Deny::UnknownCustomer,
        ),
        (
            spec("acme", "db01", "restart", "web01.acme.example", None),
            Deny::UnknownSystem,
        ),
        (
            spec("acme", "web01", "wipe", "web01.acme.example", None),
            Deny::UnknownAction,
        ),
        (
            spec("acme", "web01", "restart", "web02.acme.example", None),
            Deny::TargetNotAllowed,
        ),
        // A target that belongs to another customer is still not allowed here.
        (
            spec("acme", "web01", "restart", "web01.bravo.example", None),
            Deny::TargetNotAllowed,
        ),
        (
            spec("acme", "web01", "deploy", "web01.acme.example", None),
            Deny::PinRequired,
        ),
        (
            spec(
                "acme",
                "web01",
                "deploy",
                "web01.acme.example",
                Some(Pin::digest(&format!("sha256:{}", "ab".repeat(32))).unwrap()),
            ),
            Deny::PinWrongKind,
        ),
        (
            spec(
                "acme",
                "web01",
                "restart",
                "web01.acme.example",
                Some(Pin::commit(SHA_A).unwrap()),
            ),
            Deny::PinNotAllowed,
        ),
    ];
    for (i, (s, want)) in cases.into_iter().enumerate() {
        let got = e.submit(T0, &h, rid(i as u8), s, reason()).unwrap_err();
        assert_eq!(got, Refusal::Policy(want), "case {i}");
    }
    assert!(e.awaiting_approval(T0).is_empty());
}

#[test]
fn policy_denies_agent_not_listed_for_action() {
    let mut e = engine();
    let got = e
        .submit(T0, &agent("coder"), rid(1), restart_spec(), reason())
        .unwrap_err();
    assert_eq!(got, Refusal::Policy(Deny::AgentNotAllowed));
}

#[test]
fn empty_policy_allows_nothing() {
    let mut e = Engine::new(Policy::default());
    let got = e
        .submit(T0, &agent("hermes"), rid(1), restart_spec(), reason())
        .unwrap_err();
    assert_eq!(got, Refusal::Policy(Deny::UnknownCustomer));
}

// ------------------------------------------------------------ identifiers

#[test]
fn identifiers_reject_anything_outside_the_grammar() {
    for bad in [
        "",
        "Acme",
        "acme corp",
        "acme/../x",
        "-acme",
        "acme\n",
        "acmé",
        &"a".repeat(64),
    ] {
        assert!(CustomerId::new(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "",
        "a b",
        "a;rm",
        "$(id)",
        "a\0b",
        "a\nb",
        "../etc",
        "a/../b",
        &"a".repeat(201),
    ] {
        assert!(Target::new(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "",
        "abc",
        &SHA_A.to_uppercase(),
        &format!("{SHA_A}0"),
        &"g".repeat(40),
    ] {
        assert!(Pin::commit(bad).is_err(), "{bad:?}");
    }
    for bad in [
        "",
        SHA_A,
        "sha256:abc",
        &format!("sha512:{}", "ab".repeat(32)),
    ] {
        assert!(Pin::digest(bad).is_err(), "{bad:?}");
    }
    assert!(RequestId::new("xyz").is_err());
    assert!(Reason::new(&"x".repeat(501)).is_err());
    assert!(Reason::new("line\u{1b}[31m").is_err());
}

#[test]
fn errors_never_echo_the_input() {
    let secret = "ghp_SuperSecretTokenValue";
    let msgs = [
        CustomerId::new(secret).unwrap_err().to_string(),
        Target::new(&format!("{secret} x")).unwrap_err().to_string(),
        Pin::commit(secret).unwrap_err().to_string(),
        Reason::new(&format!("{secret}\u{0}"))
            .unwrap_err()
            .to_string(),
        format!("{:?}", CustomerId::new(secret).unwrap_err()),
    ];
    for m in msgs {
        assert!(!m.contains("ghp_") && !m.contains("Secret"), "{m}");
    }
}

// ---------------------------------------------------------------- levels

#[test]
fn level_one_is_ready_at_once_and_logged() {
    let mut e = engine();
    let s = spec("acme", "github", "read-code", "org/acme-web", None);
    let st = e.submit(T0, &agent("coder"), rid(1), s, reason()).unwrap();
    assert!(matches!(st, State::Ready { .. }));
    let d = e.fetch(T0 + 1, &agent("coder"), &rid(1)).unwrap();
    assert_eq!(d.ttl_secs, 1800);
    let kinds: Vec<_> = e.drain_events().into_iter().map(|ev| ev.kind).collect();
    assert!(kinds.iter().any(|k| matches!(
        k,
        EventKind::Requested {
            level: Level::One,
            ..
        }
    )));
    assert!(
        kinds
            .iter()
            .any(|k| matches!(k, EventKind::Delivered { .. }))
    );
}

#[test]
fn level_two_cannot_be_fetched_without_approval() {
    let mut e = engine();
    let binding = submit(&mut e, 1, restart_spec());
    let h = agent("hermes");
    assert_eq!(
        e.fetch(T0 + 1, &h, &rid(1)).unwrap_err(),
        Refusal::NotApproved
    );
    e.approve(T0 + 2, &rid(1), &binding, &cred("phone"))
        .unwrap();
    assert!(e.fetch(T0 + 3, &h, &rid(1)).is_ok());
}

#[test]
fn level_three_waits_ten_minutes_after_one_passkey() {
    let mut e = engine();
    let binding = submit(&mut e, 1, m365());
    let h = agent("hermes");
    let st = e
        .approve(T0 + 10, &rid(1), &binding, &cred("phone"))
        .unwrap();
    assert_eq!(
        st,
        State::Delayed {
            ready_at: T0 + 10 + LEVEL3_DELAY_SECS
        }
    );
    assert_eq!(
        e.fetch(T0 + 11, &h, &rid(1)).unwrap_err(),
        Refusal::DelayNotElapsed
    );
    assert_eq!(
        e.fetch(T0 + 10 + LEVEL3_DELAY_SECS - 1, &h, &rid(1))
            .unwrap_err(),
        Refusal::DelayNotElapsed
    );
    assert!(e.fetch(T0 + 10 + LEVEL3_DELAY_SECS, &h, &rid(1)).is_ok());
}

#[test]
fn level_three_delay_can_be_cancelled() {
    let mut e = engine();
    let binding = submit(&mut e, 1, m365());
    e.approve(T0 + 10, &rid(1), &binding, &cred("phone"))
        .unwrap();
    e.cancel(T0 + 60, &rid(1)).unwrap();
    let got = e
        .fetch(T0 + 10 + LEVEL3_DELAY_SECS, &agent("hermes"), &rid(1))
        .unwrap_err();
    assert_eq!(got, Refusal::Closed);
}

#[test]
fn level_three_second_passkey_must_be_a_different_one() {
    let mut e = engine();
    let binding = submit(&mut e, 1, m365());
    e.approve(T0 + 10, &rid(1), &binding, &cred("phone"))
        .unwrap();
    assert_eq!(
        e.approve(T0 + 11, &rid(1), &binding, &cred("phone"))
            .unwrap_err(),
        Refusal::SameCredential
    );
    let st = e
        .approve(T0 + 12, &rid(1), &binding, &cred("yubikey"))
        .unwrap();
    assert!(matches!(st, State::Ready { .. }));
    assert!(e.fetch(T0 + 13, &agent("hermes"), &rid(1)).is_ok());
}

// ------------------------------------------------- binding and replay

#[test]
fn approval_for_one_request_does_not_approve_another() {
    let mut e = engine();
    let b1 = submit(&mut e, 1, deploy(SHA_A));
    let b2 = submit(&mut e, 2, deploy(SHA_B));
    assert_ne!(b1, b2);
    assert_eq!(
        e.approve(T0 + 1, &rid(2), &b1, &cred("phone")).unwrap_err(),
        Refusal::BindingMismatch
    );
    // The mismatch changed nothing: request 2 is still unapproved.
    assert_eq!(
        e.fetch(T0 + 2, &agent("hermes"), &rid(2)).unwrap_err(),
        Refusal::NotApproved
    );
}

#[test]
fn binding_differs_when_any_bound_field_differs() {
    let mut e = engine();
    let base = submit(&mut e, 1, restart_spec());
    let variants = [
        submit(&mut e, 2, restart_spec()), // other request id
        submit(
            &mut e,
            3,
            spec("bravo", "web01", "restart", "web01.bravo.example", None),
        ), // customer + target
        submit(&mut e, 4, deploy(SHA_A)),  // action + pin
        submit(&mut e, 5, deploy(SHA_B)),  // pin only vs. 4
    ];
    for v in &variants {
        assert_ne!(&base, v);
    }
    assert_ne!(variants[2], variants[3]);
}

#[test]
fn binding_fields_cannot_be_shifted_into_each_other() {
    // Same concatenated text, different field boundaries.
    let a = spec("ab", "c", "restart", "t", None);
    let b = spec("a", "bc", "restart", "t", None);
    assert_ne!(
        a.binding(&rid(1), Level::Two),
        b.binding(&rid(1), Level::Two)
    );
    // Level is bound too: a level-2 signature is not valid for level 3.
    assert_ne!(
        a.binding(&rid(1), Level::Two),
        a.binding(&rid(1), Level::Three)
    );
}

#[test]
fn approval_cannot_be_reused() {
    let mut e = engine();
    let binding = submit(&mut e, 1, restart_spec());
    let h = agent("hermes");
    e.approve(T0 + 1, &rid(1), &binding, &cred("phone"))
        .unwrap();
    assert_eq!(
        e.approve(T0 + 2, &rid(1), &binding, &cred("phone"))
            .unwrap_err(),
        Refusal::AlreadyApproved
    );
    e.fetch(T0 + 3, &h, &rid(1)).unwrap();
    assert_eq!(
        e.approve(T0 + 4, &rid(1), &binding, &cred("phone"))
            .unwrap_err(),
        Refusal::Closed
    );

    // An identical new request needs its own approval; the old binding does not fit.
    e.submit(T0 + 5, &h, rid(2), restart_spec(), reason())
        .unwrap();
    assert_eq!(
        e.approve(T0 + 6, &rid(2), &binding, &cred("phone"))
            .unwrap_err(),
        Refusal::BindingMismatch
    );
}

#[test]
fn access_is_handed_out_exactly_once() {
    let mut e = engine();
    let binding = submit(&mut e, 1, restart_spec());
    let h = agent("hermes");
    e.approve(T0 + 1, &rid(1), &binding, &cred("phone"))
        .unwrap();
    let d = e.fetch(T0 + 2, &h, &rid(1)).unwrap();
    assert_eq!(d.spec, restart_spec());
    assert_eq!(d.access_expires_at, T0 + 2 + 1800);
    assert_eq!(e.fetch(T0 + 3, &h, &rid(1)).unwrap_err(), Refusal::Closed);
}

#[test]
fn request_id_cannot_be_reused() {
    let mut e = engine();
    submit(&mut e, 1, restart_spec());
    let got = e
        .submit(T0 + 1, &agent("hermes"), rid(1), restart_spec(), reason())
        .unwrap_err();
    assert_eq!(got, Refusal::DuplicateId);
}

// ---------------------------------------------------------------- owner

#[test]
fn only_the_requesting_agent_can_see_or_fetch() {
    let mut e = engine();
    let s = spec("acme", "github", "read-code", "org/acme-web", None);
    e.submit(T0, &agent("coder"), rid(1), s, reason()).unwrap();
    let other = agent("hermes");
    // Same answer as for an id that does not exist: no oracle.
    assert_eq!(
        e.fetch(T0 + 1, &other, &rid(1)).unwrap_err(),
        Refusal::UnknownRequest
    );
    assert_eq!(
        e.status(T0 + 1, &other, &rid(1)).unwrap_err(),
        Refusal::UnknownRequest
    );
    assert_eq!(
        e.withdraw(T0 + 1, &other, &rid(1)).unwrap_err(),
        Refusal::UnknownRequest
    );
    assert_eq!(
        e.fetch(T0 + 1, &other, &rid(9)).unwrap_err(),
        Refusal::UnknownRequest
    );
    assert!(e.fetch(T0 + 2, &agent("coder"), &rid(1)).is_ok());
}

// --------------------------------------------------------------- expiry

#[test]
fn unapproved_request_expires_after_five_minutes() {
    let mut e = engine();
    let binding = submit(&mut e, 1, restart_spec());
    assert_eq!(APPROVAL_WINDOW_SECS, 300);
    assert_eq!(e.awaiting_approval(T0 + 299).len(), 1);
    assert!(e.awaiting_approval(T0 + 300).is_empty());
    assert_eq!(
        e.approve(T0 + 300, &rid(1), &binding, &cred("phone"))
            .unwrap_err(),
        Refusal::Closed
    );
    assert_eq!(
        e.status(T0 + 300, &agent("hermes"), &rid(1)).unwrap(),
        State::Expired
    );
}

#[test]
fn approved_access_expires_if_not_fetched_in_five_minutes() {
    let mut e = engine();
    let binding = submit(&mut e, 1, restart_spec());
    e.approve(T0 + 100, &rid(1), &binding, &cred("phone"))
        .unwrap();
    let got = e
        .fetch(T0 + 100 + FETCH_WINDOW_SECS, &agent("hermes"), &rid(1))
        .unwrap_err();
    assert_eq!(got, Refusal::Closed);
}

#[test]
fn level_three_fetch_window_starts_when_the_delay_ends() {
    let mut e = engine();
    let binding = submit(&mut e, 1, m365());
    e.approve(T0, &rid(1), &binding, &cred("phone")).unwrap();
    let ready = T0 + LEVEL3_DELAY_SECS;
    // Nobody looked at the engine for a long time: it must still expire.
    let got = e
        .fetch(ready + FETCH_WINDOW_SECS, &agent("hermes"), &rid(1))
        .unwrap_err();
    assert_eq!(got, Refusal::Closed);
    assert_eq!(
        e.status(ready + FETCH_WINDOW_SECS, &agent("hermes"), &rid(1))
            .unwrap(),
        State::Expired
    );
}

#[test]
fn delivered_access_is_marked_expired_after_its_ttl() {
    let mut e = engine();
    let binding = submit(&mut e, 1, restart_spec());
    let h = agent("hermes");
    e.approve(T0, &rid(1), &binding, &cred("phone")).unwrap();
    e.fetch(T0 + 1, &h, &rid(1)).unwrap();
    assert!(matches!(
        e.status(T0 + 2, &h, &rid(1)).unwrap(),
        State::Delivered { .. }
    ));
    assert_eq!(
        e.status(T0 + 1 + 1800, &h, &rid(1)).unwrap(),
        State::AccessExpired
    );
    let kinds: Vec<_> = e.drain_events().into_iter().map(|ev| ev.kind).collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| matches!(k, EventKind::AccessExpired))
            .count(),
        1
    );
}

// ------------------------------------------------------ cancel and flood

#[test]
fn cancel_and_withdraw_close_the_request() {
    let mut e = engine();
    let h = agent("hermes");
    let b1 = submit(&mut e, 1, restart_spec());
    let b2 = submit(&mut e, 2, restart_spec());
    e.cancel(T0 + 1, &rid(1)).unwrap();
    e.withdraw(T0 + 1, &h, &rid(2)).unwrap();
    assert_eq!(
        e.approve(T0 + 2, &rid(1), &b1, &cred("phone")).unwrap_err(),
        Refusal::Closed
    );
    assert_eq!(
        e.approve(T0 + 2, &rid(2), &b2, &cred("phone")).unwrap_err(),
        Refusal::Closed
    );
    assert_eq!(e.cancel(T0 + 3, &rid(1)).unwrap_err(), Refusal::Closed);
}

#[test]
fn an_agent_cannot_flood_the_approval_page() {
    let mut e = engine();
    let h = agent("hermes");
    for n in 0..MAX_OPEN_PER_AGENT as u8 {
        e.submit(T0, &h, rid(n), restart_spec(), reason()).unwrap();
    }
    assert_eq!(
        e.submit(T0, &h, rid(100), restart_spec(), reason())
            .unwrap_err(),
        Refusal::TooManyOpen
    );
    assert_eq!(e.awaiting_approval(T0).len(), MAX_OPEN_PER_AGENT);
    // Closed requests free their slot.
    e.cancel(T0 + 1, &rid(0)).unwrap();
    assert!(
        e.submit(T0 + 1, &h, rid(101), restart_spec(), reason())
            .is_ok()
    );
}

// ------------------------------------------------------- emergency stop

#[test]
fn emergency_stop_revokes_everything_and_refuses_everything() {
    let mut e = engine();
    let h = agent("hermes");
    let b1 = submit(&mut e, 1, restart_spec()); // will be delivered
    let b2 = submit(&mut e, 2, restart_spec()); // approved, not fetched
    let b3 = submit(&mut e, 3, m365()); // in level-3 delay
    let b4 = submit(&mut e, 4, deploy(SHA_A)); // pending
    e.approve(T0 + 1, &rid(1), &b1, &cred("phone")).unwrap();
    e.fetch(T0 + 2, &h, &rid(1)).unwrap();
    e.approve(T0 + 1, &rid(2), &b2, &cred("phone")).unwrap();
    e.approve(T0 + 1, &rid(3), &b3, &cred("phone")).unwrap();

    let live = e.emergency_stop(T0 + 10);
    // Only the delivered, still-valid access needs revoking at its issuer.
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, rid(1));
    assert!(e.is_stopped());

    assert_eq!(e.fetch(T0 + 11, &h, &rid(2)).unwrap_err(), Refusal::Stopped);
    assert_eq!(
        e.approve(T0 + 11, &rid(4), &b4, &cred("phone"))
            .unwrap_err(),
        Refusal::Stopped
    );
    assert_eq!(
        e.submit(T0 + 11, &h, rid(5), restart_spec(), reason())
            .unwrap_err(),
        Refusal::Stopped
    );
    assert!(e.awaiting_approval(T0 + 11).is_empty());

    // Turning Key-Box back on does not bring old requests back.
    e.resume(T0 + 20);
    assert!(!e.is_stopped());
    for n in 1..=4 {
        assert_eq!(
            e.status(T0 + 21, &h, &rid(n)).unwrap(),
            State::Revoked,
            "request {n}"
        );
    }
    assert_eq!(e.fetch(T0 + 21, &h, &rid(2)).unwrap_err(), Refusal::Closed);
    assert_eq!(
        e.fetch(T0 + 20 + LEVEL3_DELAY_SECS, &h, &rid(3))
            .unwrap_err(),
        Refusal::Closed
    );
    assert!(
        e.submit(T0 + 21, &h, rid(6), restart_spec(), reason())
            .is_ok()
    );
}

// ------------------------------------------------------------------ log

#[test]
fn every_decision_leaves_an_event() {
    let mut e = engine();
    let h = agent("hermes");
    let bad = spec("acme", "web01", "wipe", "web01.acme.example", None);
    let _ = e.submit(T0, &h, rid(1), bad, reason());
    let b = submit(&mut e, 2, restart_spec());
    let _ = e.approve(T0 + 1, &rid(2), b"wrong", &cred("phone"));
    e.approve(T0 + 2, &rid(2), &b, &cred("phone")).unwrap();
    e.fetch(T0 + 3, &h, &rid(2)).unwrap();
    let _ = e.fetch(T0 + 4, &h, &rid(2));
    e.emergency_stop(T0 + 5);
    e.resume(T0 + 6);

    let kinds: Vec<_> = e.drain_events().into_iter().map(|ev| ev.kind).collect();
    let has = |f: fn(&EventKind) -> bool| kinds.iter().any(f);
    assert!(has(|k| matches!(
        k,
        EventKind::Refused(Refusal::Policy(Deny::UnknownAction))
    )));
    assert!(has(|k| matches!(k, EventKind::Requested { .. })));
    assert!(has(|k| matches!(
        k,
        EventKind::Refused(Refusal::BindingMismatch)
    )));
    assert!(has(|k| matches!(k, EventKind::Approved { .. })));
    assert!(has(|k| matches!(k, EventKind::Ready)));
    assert!(has(|k| matches!(k, EventKind::Delivered { .. })));
    assert!(has(|k| matches!(k, EventKind::Refused(Refusal::Closed))));
    assert!(has(|k| matches!(k, EventKind::EmergencyStop)));
    assert!(has(|k| matches!(k, EventKind::Revoked)));
    assert!(has(|k| matches!(k, EventKind::Resumed)));
    assert!(e.drain_events().is_empty());
}

// ------------------------------------------------------------- restarts

/// Take a snapshot and start a new engine from it, as a restart does.
fn restart(e: &Engine, p: Policy, now: u64) -> Engine {
    let (stopped, saved) = e.snapshot();
    Engine::restore(p, stopped, saved, now)
}

#[test]
fn a_restart_changes_nothing_about_what_is_allowed() {
    let mut e = engine();
    let h = agent("hermes");
    let b1 = submit(&mut e, 1, restart_spec()); // approved, not fetched
    let b2 = submit(&mut e, 2, restart_spec()); // pending
    let b3 = submit(&mut e, 3, m365()); // level 3, in its delay
    let b4 = submit(&mut e, 4, restart_spec()); // delivered
    e.approve(T0 + 1, &rid(1), &b1, &cred("phone")).unwrap();
    e.approve(T0 + 1, &rid(3), &b3, &cred("phone")).unwrap();
    e.approve(T0 + 1, &rid(4), &b4, &cred("phone")).unwrap();
    e.fetch(T0 + 2, &h, &rid(4)).unwrap();

    let mut e = restart(&e, policy(), T0 + 3);
    assert!(!e.is_stopped());
    // Delivered stays delivered: a restart is not a second chance to fetch.
    assert_eq!(e.fetch(T0 + 4, &h, &rid(4)).unwrap_err(), Refusal::Closed);
    // Pending is still pending and still needs the same signature.
    assert_eq!(
        e.fetch(T0 + 4, &h, &rid(2)).unwrap_err(),
        Refusal::NotApproved
    );
    assert_eq!(e.binding(&rid(2)).unwrap(), b2.as_slice());
    // The level-3 delay kept its clock, and the first passkey is remembered.
    assert_eq!(
        e.fetch(T0 + 4, &h, &rid(3)).unwrap_err(),
        Refusal::DelayNotElapsed
    );
    assert_eq!(
        e.approve(T0 + 5, &rid(3), &b3, &cred("phone")).unwrap_err(),
        Refusal::SameCredential
    );
    // Approved is still ready, once.
    assert!(e.fetch(T0 + 6, &h, &rid(1)).is_ok());
    assert_eq!(e.fetch(T0 + 7, &h, &rid(1)).unwrap_err(), Refusal::Closed);
    // Much later the delay has run out, and the level-3 request can be fetched.
    assert!(e.fetch(T0 + 1 + LEVEL3_DELAY_SECS, &h, &rid(3)).is_ok());
    // An old id cannot be taken again after a restart either.
    assert_eq!(
        e.submit(T0 + 8, &h, rid(2), restart_spec(), reason())
            .unwrap_err(),
        Refusal::DuplicateId
    );
}

#[test]
fn time_that_passed_while_key_box_was_down_still_counts() {
    let mut e = engine();
    let h = agent("hermes");
    let b1 = submit(&mut e, 1, restart_spec());
    submit(&mut e, 2, restart_spec());
    e.approve(T0 + 1, &rid(1), &b1, &cred("phone")).unwrap();
    let mut e = restart(&e, policy(), T0 + 1000);
    assert_eq!(e.status(T0 + 1000, &h, &rid(1)).unwrap(), State::Expired);
    assert_eq!(e.status(T0 + 1000, &h, &rid(2)).unwrap(), State::Expired);
}

#[test]
fn an_emergency_stop_survives_a_restart() {
    let mut e = engine();
    let h = agent("hermes");
    let b1 = submit(&mut e, 1, restart_spec());
    e.emergency_stop(T0 + 1);
    let mut e = restart(&e, policy(), T0 + 2);
    assert!(e.is_stopped());
    assert_eq!(
        e.submit(T0 + 3, &h, rid(2), restart_spec(), reason())
            .unwrap_err(),
        Refusal::Stopped
    );
    assert_eq!(
        e.approve(T0 + 3, &rid(1), &b1, &cred("phone")).unwrap_err(),
        Refusal::Stopped
    );
    e.resume(T0 + 4);
    let mut e = restart(&e, policy(), T0 + 5);
    assert!(!e.is_stopped());
    assert_eq!(e.status(T0 + 5, &h, &rid(1)).unwrap(), State::Revoked);
}

#[test]
fn an_approval_is_not_carried_into_a_changed_policy() {
    let mut e = engine();
    let h = agent("hermes");
    let b1 = submit(&mut e, 1, restart_spec()); // approved
    submit(&mut e, 2, restart_spec()); // pending
    e.approve(T0 + 1, &rid(1), &b1, &cred("phone")).unwrap();

    // The action is gone from the new policy.
    let mut e2 = restart(&e, Policy::default(), T0 + 2);
    assert_eq!(e2.fetch(T0 + 3, &h, &rid(1)).unwrap_err(), Refusal::Closed);
    assert_eq!(e2.status(T0 + 3, &h, &rid(2)).unwrap(), State::Revoked);
    assert!(
        e2.drain_events()
            .iter()
            .any(|ev| ev.kind == EventKind::Revoked)
    );

    // The action is now level 3: the level-2 approval does not count for it.
    let mut stricter = Policy::default();
    stricter.insert(
        CustomerId::new("acme").unwrap(),
        SystemId::new("web01").unwrap(),
        ActionId::new("restart").unwrap(),
        rule(Level::Three, &["hermes"], &["web01.acme.example"], None),
    );
    let mut e3 = restart(&e, stricter, T0 + 2);
    assert_eq!(e3.fetch(T0 + 3, &h, &rid(1)).unwrap_err(), Refusal::Closed);
}

#[test]
fn closed_requests_are_forgotten_after_a_day_open_ones_never() {
    let mut e = engine();
    let h = agent("hermes");
    submit(&mut e, 1, restart_spec());
    e.cancel(T0 + 1, &rid(1)).unwrap();
    assert_eq!(
        e.status(T0 + KEEP_CLOSED_SECS - 1, &h, &rid(1)).unwrap(),
        State::Cancelled
    );
    assert_eq!(
        e.status(T0 + KEEP_CLOSED_SECS, &h, &rid(1)).unwrap_err(),
        Refusal::UnknownRequest
    );
    assert!(e.snapshot().1.is_empty());
}
