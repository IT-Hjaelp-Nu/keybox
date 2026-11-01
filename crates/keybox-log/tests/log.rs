//! The audit log: every change to a written line must be detectable.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use keybox_core::engine::{Engine, Event, EventKind, Refusal};
use keybox_core::ident::{
    ActionId, AgentId, CredentialId, CustomerId, Pin, RequestId, SystemId, Target,
};
use keybox_core::policy::{ActionRule, Deny, Level, Policy};
use keybox_core::request::{Reason, RequestSpec};
use keybox_log::{AuditLog, LogError, Record, verify};

fn path(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{name}-{}-{n}.log", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn rid(n: u8) -> RequestId {
    RequestId::new(&format!("{n:032x}")).unwrap()
}

fn event(at: u64, n: u8, kind: EventKind) -> Event {
    Event {
        at,
        request: Some(rid(n)),
        agent: Some(AgentId::new("hermes").unwrap()),
        kind,
    }
}

fn spec() -> RequestSpec {
    RequestSpec {
        customer: CustomerId::new("acme").unwrap(),
        system: SystemId::new("web01").unwrap(),
        action: ActionId::new("deploy").unwrap(),
        target: Target::new("web01.acme.example").unwrap(),
        pin: Some(Pin::commit(&"ab".repeat(20)).unwrap()),
    }
}

/// A log with five lines.
fn filled(name: &str) -> PathBuf {
    let p = path(name);
    let mut log = AuditLog::open(&p).unwrap();
    log.append(
        &event(
            10,
            1,
            EventKind::Requested {
                spec: spec(),
                level: Level::Two,
                reason: Reason::new("kunden bad om det").unwrap(),
            },
        )
        .into(),
    )
    .unwrap();
    log.append(
        &event(
            11,
            1,
            EventKind::Approved {
                credential: CredentialId::new("phone").unwrap(),
            },
        )
        .into(),
    )
    .unwrap();
    log.append(&event(11, 1, EventKind::Ready).into()).unwrap();
    log.append(
        &event(
            12,
            1,
            EventKind::Delivered {
                access_expires_at: 1812,
            },
        )
        .into(),
    )
    .unwrap();
    log.append(
        &event(
            13,
            2,
            EventKind::Refused(Refusal::Policy(Deny::UnknownAction)),
        )
        .into(),
    )
    .unwrap();
    p
}

fn lines(p: &PathBuf) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(p: &PathBuf, lines: &[String]) {
    fs::write(
        p,
        lines.iter().map(|l| format!("{l}\n")).collect::<String>(),
    )
    .unwrap();
}

#[test]
fn empty_log_verifies_and_has_the_genesis_head() {
    let p = path("empty");
    let log = AuditLog::open(&p).unwrap();
    assert_eq!(log.head().seq, 0);
    assert_eq!(log.head().hash, "0".repeat(64));
    assert_eq!(verify(&p).unwrap(), log.head());
}

#[test]
fn appended_lines_form_a_chain() {
    let p = filled("chain");
    let head = verify(&p).unwrap();
    assert_eq!(head.seq, 5);
    let ls = lines(&p);
    assert_eq!(ls.len(), 5);
    // Each line starts with its own hash, then the hash of the line before.
    for i in 1..ls.len() {
        let prev_hash = ls[i - 1].split(' ').next().unwrap();
        assert_eq!(ls[i].split(' ').nth(1).unwrap(), prev_hash);
    }
    assert!(ls[4].starts_with(&head.hash));
}

#[test]
fn log_contains_what_happened() {
    let p = filled("content");
    let text = fs::read_to_string(&p).unwrap();
    for want in [
        "\"kind\":\"requested\"",
        "\"customer\":\"acme\"",
        "\"action\":\"deploy\"",
        "\"target\":\"web01.acme.example\"",
        &format!("\"commit\":\"{}\"", "ab".repeat(20)),
        "\"level\":2",
        "\"reason\":\"kunden bad om det\"",
        "\"kind\":\"approved\"",
        "\"credential\":\"phone\"",
        "\"kind\":\"delivered\"",
        "\"access_expires_at\":1812",
        "\"kind\":\"refused\"",
        "\"why\":\"policy:unknown-action\"",
        "\"agent\":\"hermes\"",
    ] {
        assert!(text.contains(want), "missing {want} in:\n{text}");
    }
}

#[test]
fn reopening_continues_the_same_chain() {
    let p = filled("reopen");
    let before = verify(&p).unwrap();
    let mut log = AuditLog::open(&p).unwrap();
    assert_eq!(log.head(), before);
    log.append(&event(20, 3, EventKind::Expired).into())
        .unwrap();
    let after = verify(&p).unwrap();
    assert_eq!(after.seq, 6);
    assert_ne!(after.hash, before.hash);
    assert_eq!(lines(&p)[5].split(' ').nth(1).unwrap(), before.hash);
}

#[test]
fn changing_any_single_character_is_detected() {
    let p = filled("flip");
    let original = fs::read(&p).unwrap();
    for i in 0..original.len() {
        if original[i] == b'\n' {
            continue;
        }
        let mut bytes = original.clone();
        bytes[i] = if bytes[i] == b'x' { b'y' } else { b'x' };
        fs::write(&p, &bytes).unwrap();
        assert!(verify(&p).is_err(), "change at byte {i} went unnoticed");
    }
}

#[test]
fn removing_reordering_or_inserting_lines_is_detected() {
    let p = filled("lines");
    let ls = lines(&p);

    let mut removed = ls.clone();
    removed.remove(2);
    write_lines(&p, &removed);
    assert_eq!(verify(&p), Err(LogError::Broken { line: 3 }));

    let mut first_gone = ls.clone();
    first_gone.remove(0);
    write_lines(&p, &first_gone);
    assert_eq!(verify(&p), Err(LogError::Broken { line: 1 }));

    let mut swapped = ls.clone();
    swapped.swap(1, 2);
    write_lines(&p, &swapped);
    assert_eq!(verify(&p), Err(LogError::Broken { line: 2 }));

    let mut repeated = ls.clone();
    repeated.insert(3, ls[2].clone());
    write_lines(&p, &repeated);
    assert_eq!(verify(&p), Err(LogError::Broken { line: 4 }));

    write_lines(&p, &ls);
    assert!(verify(&p).is_ok());
}

#[test]
fn a_rewritten_line_with_a_recomputed_hash_breaks_the_next_line() {
    // An attacker who edits line 2 and fixes that line's own hash still
    // cannot make line 3 point at it without rewriting everything after.
    let p = filled("rehash");
    let mut ls = lines(&p);
    let (prev, body) = {
        let mut parts = ls[1].splitn(3, ' ');
        (
            parts.nth(1).unwrap().to_owned(),
            parts.next().unwrap().replace("phone", "yubikey"),
        )
    };
    let input = format!("{prev}\n{body}");
    let hash: String = ring::digest::digest(&ring::digest::SHA256, input.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ls[1] = format!("{hash} {prev} {body}");
    write_lines(&p, &ls);
    assert_eq!(verify(&p), Err(LogError::Broken { line: 3 }));
}

#[test]
fn cutting_off_the_end_changes_the_head() {
    // A chain cannot show that its newest lines were removed. The head can:
    // it is what Christian compares against a copy kept elsewhere.
    let p = filled("truncate");
    let full = verify(&p).unwrap();
    let mut ls = lines(&p);
    ls.truncate(3);
    write_lines(&p, &ls);
    let cut = verify(&p).unwrap();
    assert_eq!(cut.seq, 3);
    assert_ne!(cut, full);
}

#[test]
fn a_half_written_last_line_is_refused() {
    let p = filled("torn");
    let mut bytes = fs::read(&p).unwrap();
    bytes.truncate(bytes.len() - 10);
    fs::write(&p, &bytes).unwrap();
    assert_eq!(verify(&p), Err(LogError::Broken { line: 5 }));
}

#[test]
fn a_damaged_log_cannot_be_opened_for_writing() {
    let p = filled("refuse");
    let mut ls = lines(&p);
    ls[0] = ls[0].replace("acme", "evil");
    write_lines(&p, &ls);
    assert!(matches!(
        AuditLog::open(&p),
        Err(LogError::Broken { line: 1 })
    ));
}

#[test]
fn only_one_writer_at_a_time() {
    let p = path("lock");
    let _first = AuditLog::open(&p).unwrap();
    assert!(matches!(AuditLog::open(&p), Err(LogError::Locked)));
}

#[test]
fn file_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let p = filled("mode");
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn agent_text_cannot_forge_a_line() {
    let p = path("inject");
    let mut log = AuditLog::open(&p).unwrap();
    // No control characters can be in a Reason, but quotes and backslashes can.
    let reason = Reason::new("ok\",\"kind\":\"approved\"} \\ 0000 {\"x\":\"").unwrap();
    log.append(&Record::new(5, "note").with("reason", &reason))
        .unwrap();
    log.append(&event(6, 1, EventKind::Ready).into()).unwrap();
    assert_eq!(lines(&p).len(), 2);
    assert_eq!(verify(&p).unwrap().seq, 2);
    assert!(!lines(&p)[0].contains("\"kind\":\"approved\""));
}

#[test]
fn every_engine_event_can_be_logged() {
    let mut policy = Policy::default();
    let hermes = AgentId::new("hermes").unwrap();
    policy.insert(
        CustomerId::new("acme").unwrap(),
        SystemId::new("web01").unwrap(),
        ActionId::new("deploy").unwrap(),
        ActionRule {
            level: Level::Three,
            agents: [hermes.clone()].into(),
            targets: [Target::new("web01.acme.example").unwrap()].into(),
            pin: Some(keybox_core::ident::PinKind::Commit),
            ttl_secs: 60,
        },
    );
    let mut e = Engine::new(policy);
    let reason = Reason::new("test").unwrap();
    let phone = CredentialId::new("phone").unwrap();
    for n in 1..=4 {
        e.submit(0, &hermes, rid(n), spec(), reason.clone())
            .unwrap();
    }
    let b = |e: &Engine, n| e.binding(&rid(n)).unwrap().to_vec();
    let (b1, b2) = (b(&e, 1), b(&e, 2));
    e.approve(1, &rid(1), &b1, &phone).unwrap();
    let _ = e.approve(1, &rid(1), &b1, &phone);
    e.approve(2, &rid(2), &b2, &phone).unwrap();
    e.cancel(3, &rid(2)).unwrap();
    e.withdraw(3, &hermes, &rid(3)).unwrap();
    e.fetch(700, &hermes, &rid(1)).unwrap();
    e.status(800, &hermes, &rid(1)).unwrap();
    e.emergency_stop(900);
    e.resume(901);

    let p = path("all-events");
    let mut log = AuditLog::open(&p).unwrap();
    let events = e.drain_events();
    for ev in &events {
        log.append(&ev.into()).unwrap();
    }
    assert_eq!(verify(&p).unwrap().seq, events.len() as u64);
    let text = fs::read_to_string(&p).unwrap();
    for kind in [
        "requested",
        "approved",
        "delayed",
        "ready",
        "delivered",
        "cancelled",
        "withdrawn",
        "expired",
        "access-expired",
        "emergency-stop",
        "resumed",
        "refused",
    ] {
        assert!(
            text.contains(&format!("\"kind\":\"{kind}\"")),
            "no {kind} line"
        );
    }
}
