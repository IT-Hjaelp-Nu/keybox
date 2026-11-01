//! What Key-Box remembers when it is stopped and started again.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Box, POLICY, READ, RESTART, agent, site};
use keybox_api::{Outcome, handle};
use keybox_core::ident::{CredentialId, RequestId};
use keyboxd::Error;
use keyboxd::core::Core;
use keyboxd::store::STATE_FILE;

fn rid(n: u8) -> RequestId {
    RequestId::new(&format!("{n:032x}")).unwrap()
}

fn open(b: &Box) -> Core {
    Core::open(&b.dir, site()).unwrap()
}

/// A new Key-Box with the test policy approved.
fn fresh(b: &Box) -> Core {
    let mut core = open(b);
    core.install_policy(
        keyboxd::now(),
        vec![("test.toml".to_owned(), POLICY.to_owned())],
    )
    .unwrap();
    core
}

/// One agent line, saved and logged the way the daemon does it.
fn call(core: &mut Core, n: u8, line: &str) -> String {
    let out = handle(
        &mut core.engine,
        keyboxd::now(),
        &agent("hermes"),
        rid(n),
        line.as_bytes(),
    );
    core.commit().unwrap();
    match out {
        Outcome::Reply(reply) => reply,
        Outcome::Issue { .. } => "ISSUE".into(),
    }
}

fn fetch(core: &mut Core, n: u8) -> String {
    call(core, 200, &format!(r#"{{"op":"fetch","id":"{}"}}"#, rid(n)))
}

fn approve(core: &mut Core, n: u8) {
    let binding = core.engine.binding(&rid(n)).unwrap().to_vec();
    let phone = CredentialId::new("phone").unwrap();
    core.engine
        .approve(keyboxd::now(), &rid(n), &binding, &phone)
        .unwrap();
    core.commit().unwrap();
}

#[test]
fn requests_keep_their_state_across_a_restart() {
    let b = Box::new("restart-state");
    let mut core = fresh(&b);
    call(&mut core, 1, RESTART); // will be approved
    call(&mut core, 2, RESTART); // stays pending
    call(&mut core, 3, READ); // level 1, fetched before the restart
    approve(&mut core, 1);
    assert_eq!(fetch(&mut core, 3), "ISSUE");
    drop(core);

    let mut core = open(&b);
    // Fetched once is fetched: a restart is not a second chance.
    assert_eq!(fetch(&mut core, 3), r#"{"error":"closed","ok":false}"#);
    assert_eq!(
        fetch(&mut core, 2),
        r#"{"error":"not-approved","ok":false}"#
    );
    assert_eq!(fetch(&mut core, 1), "ISSUE");
    drop(core);

    let mut core = open(&b);
    assert_eq!(fetch(&mut core, 1), r#"{"error":"closed","ok":false}"#);
    assert!(keybox_log::verify(&b.log()).is_ok());
}

#[test]
fn an_emergency_stop_is_still_on_after_a_restart() {
    let b = Box::new("restart-stop");
    let mut core = fresh(&b);
    call(&mut core, 1, RESTART);
    approve(&mut core, 1);
    core.engine.emergency_stop(keyboxd::now());
    core.commit().unwrap();
    drop(core);

    let mut core = open(&b);
    assert!(core.engine.is_stopped());
    let stopped = r#"{"error":"stopped","ok":false}"#;
    assert_eq!(call(&mut core, 2, RESTART), stopped);
    assert_eq!(fetch(&mut core, 1), stopped);
    core.engine.resume(keyboxd::now());
    core.commit().unwrap();
    drop(core);

    let mut core = open(&b);
    assert!(!core.engine.is_stopped());
    // What was approved before the stop does not come back.
    assert_eq!(fetch(&mut core, 1), r#"{"error":"closed","ok":false}"#);
    assert!(call(&mut core, 3, RESTART).contains(r#""state":"pending""#));
}

#[test]
fn an_approval_does_not_survive_a_policy_that_no_longer_allows_it() {
    let b = Box::new("restart-policy");
    let mut core = fresh(&b);
    call(&mut core, 1, RESTART);
    approve(&mut core, 1);
    drop(core);

    // A new policy without that action is approved while Key-Box is down
    // for nobody: here simply put into force.
    let mut core = open(&b);
    core.install_policy(keyboxd::now(), Vec::new()).unwrap();
    assert_eq!(fetch(&mut core, 1), r#"{"error":"closed","ok":false}"#);
    drop(core);
    assert!(b.log_text().contains(r#""kind":"revoked""#));
}

#[test]
fn the_state_file_is_private_and_checked_when_read() {
    let b = Box::new("restart-file");
    let mut core = fresh(&b);
    call(&mut core, 1, RESTART);
    drop(core);
    let path = b.dir.join(STATE_FILE);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Rows that do not fit the grammar stop Key-Box from starting, whatever
    // they would have meant: a level it does not know, a customer name with
    // capitals, a state that does not exist.
    for change in [
        "UPDATE requests SET level = 0",
        "UPDATE requests SET customer = 'Acme Corp'",
        "UPDATE requests SET state = 'approved-by-magic'",
        "UPDATE requests SET state = 'ready', state_time = NULL",
        "UPDATE requests SET pin_kind = 'commit', pin = 'main'",
        "UPDATE requests SET id = 'abc'",
    ] {
        let copy = b.dir.join("copy");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::copy(&path, copy.join(STATE_FILE)).unwrap();
        rusqlite::Connection::open(copy.join(STATE_FILE))
            .unwrap()
            .execute(change, [])
            .unwrap();
        let out = Core::open(&copy, site());
        assert!(matches!(out, Err(Error::Storage)), "{change}");
        std::fs::remove_dir_all(&copy).unwrap();
    }

    // A state file from a newer Key-Box is refused too.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA user_version = 99")
        .unwrap();
    assert!(matches!(Core::open(&b.dir, site()), Err(Error::Storage)));
}

#[test]
fn a_state_file_from_before_policy_approval_is_upgraded_in_place() {
    // Version 1 of the file, as PR #15 wrote it: no table for the policy.
    let b = Box::new("restart-upgrade");
    let conn = rusqlite::Connection::open(b.dir.join(STATE_FILE)).unwrap();
    conn.execute_batch(
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
         CREATE TABLE requests (
             id TEXT PRIMARY KEY, agent TEXT NOT NULL, customer TEXT NOT NULL,
             system TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
             pin_kind TEXT, pin TEXT, reason TEXT NOT NULL, level INTEGER NOT NULL,
             ttl_secs INTEGER NOT NULL, first_approver TEXT, state TEXT NOT NULL,
             state_time INTEGER, created_at INTEGER NOT NULL) STRICT;
         INSERT INTO meta VALUES ('stopped', 'yes');
         INSERT INTO meta VALUES ('github-suspended', '4242');
         INSERT INTO requests VALUES ('00000000000000000000000000000001', 'hermes', 'acme', 'web01',
             'restart', 'web01.acme.example', NULL, NULL, 'gammel', 2, 1800, NULL, 'pending', 9999999999,
             CAST(strftime('%s', 'now') AS INTEGER));
         PRAGMA user_version = 1;",
    )
    .unwrap();
    drop(conn);

    let mut core = open(&b);
    // What the old file said still holds: the stop, and what it suspended.
    assert!(core.engine.is_stopped());
    assert_eq!(core.github_suspended(), [4242]);
    // There is no approved policy yet, so nothing is allowed and the old
    // open request is revoked rather than carried along.
    assert_eq!(core.loaded.actions().count(), 0);
    assert_eq!(
        core.engine
            .status(keyboxd::now(), &agent("hermes"), &rid(1))
            .unwrap(),
        keybox_core::engine::State::Revoked
    );
    drop(core);
    // And it opens again as the new version.
    let core = open(&b);
    assert!(core.engine.is_stopped());
}
