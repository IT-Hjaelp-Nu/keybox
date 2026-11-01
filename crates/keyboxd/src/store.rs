//! Key-Box' memory across restarts: whether the emergency stop is on, and
//! every request that is still remembered.
//!
//! The whole picture is written in one transaction each time it changes, and
//! the daemon answers nobody before that write is on disk. What is read back
//! at start is checked like any other input: a row that does not fit the
//! grammar stops Key-Box from starting rather than being skipped.

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use keybox_core::engine::{Saved, State};
use keybox_core::ident::{
    ActionId, AgentId, CredentialId, CustomerId, Pin, PinKind, RequestId, SystemId, Target,
};
use keybox_core::policy::Level;
use keybox_core::request::{Reason, RequestSpec};
use rusqlite::{Connection, params};

use crate::Error;

pub const STATE_FILE: &str = "state.db";
const SCHEMA_VERSION: i64 = 2;

/// Added in version 2: the policy as Christian last approved it.
const POLICY_TABLE: &str =
    "CREATE TABLE policy_files (name TEXT PRIMARY KEY, content TEXT NOT NULL) STRICT;";

pub struct Store {
    conn: Connection,
}

fn bad<E>(_: E) -> Error {
    Error::Storage
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, Error> {
        let path = dir.join(STATE_FILE);
        // Created private to Key-Box before SQLite ever writes to it.
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        let conn = Connection::open(&path).map_err(bad)?;
        // FULL: a committed write has reached the disk when the call returns.
        conn.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL;")
            .map_err(bad)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(bad)?;
        match version {
            0 => conn
                .execute_batch(&format!(
                    "BEGIN;
                     CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
                     CREATE TABLE requests (
                         id TEXT PRIMARY KEY, agent TEXT NOT NULL, customer TEXT NOT NULL,
                         system TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
                         pin_kind TEXT, pin TEXT, reason TEXT NOT NULL, level INTEGER NOT NULL,
                         ttl_secs INTEGER NOT NULL, first_approver TEXT, state TEXT NOT NULL,
                         state_time INTEGER, created_at INTEGER NOT NULL) STRICT;
                     {POLICY_TABLE}
                     PRAGMA user_version = {SCHEMA_VERSION};
                     COMMIT;"
                ))
                .map_err(bad)?,
            1 => conn
                .execute_batch(&format!(
                    "BEGIN; {POLICY_TABLE} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
                ))
                .map_err(bad)?,
            SCHEMA_VERSION => {}
            // Written by a newer Key-Box: do not guess at its meaning.
            _ => return Err(Error::Storage),
        }
        Ok(Self { conn })
    }

    /// The stop flag and the requests, as last saved.
    pub fn load(&self) -> Result<(bool, Vec<Saved>), Error> {
        let stopped = self.meta("stopped")?.as_deref() == Some("yes");
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, agent, customer, system, action, target, pin_kind, pin, reason, level,
                        ttl_secs, first_approver, state, state_time, created_at FROM requests",
            )
            .map_err(bad)?;
        type Row = (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            i64,
            i64,
            Option<String>,
            String,
            Option<i64>,
            i64,
        );
        let rows = statement
            .query_map([], |r| {
                Ok::<Row, rusqlite::Error>((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                ))
            })
            .map_err(bad)?;
        let mut saved = Vec::new();
        for row in rows {
            let (
                id,
                agent,
                customer,
                system,
                action,
                target,
                pin_kind,
                pin,
                reason,
                level,
                ttl,
                first,
                state,
                time,
                created,
            ) = row.map_err(bad)?;
            let pin = match (pin_kind.as_deref(), pin) {
                (None, None) => None,
                (Some("commit"), Some(p)) => Some(Pin::commit(&p).map_err(bad)?),
                (Some("digest"), Some(p)) => Some(Pin::digest(&p).map_err(bad)?),
                _ => return Err(Error::Storage),
            };
            let time = || u64::try_from(time.ok_or(Error::Storage)?).map_err(bad);
            saved.push(Saved {
                id: RequestId::new(&id).map_err(bad)?,
                agent: AgentId::new(&agent).map_err(bad)?,
                spec: RequestSpec {
                    customer: CustomerId::new(&customer).map_err(bad)?,
                    system: SystemId::new(&system).map_err(bad)?,
                    action: ActionId::new(&action).map_err(bad)?,
                    target: Target::new(&target).map_err(bad)?,
                    pin,
                },
                reason: Reason::new(&reason).map_err(bad)?,
                level: match level {
                    1 => Level::One,
                    2 => Level::Two,
                    3 => Level::Three,
                    _ => return Err(Error::Storage),
                },
                ttl_secs: u64::try_from(ttl).map_err(bad)?,
                first_approver: first
                    .map(|c| CredentialId::new(&c))
                    .transpose()
                    .map_err(bad)?,
                state: match state.as_str() {
                    "pending" => State::Pending {
                        expires_at: time()?,
                    },
                    "delayed" => State::Delayed { ready_at: time()? },
                    "ready" => State::Ready {
                        expires_at: time()?,
                    },
                    "delivered" => State::Delivered {
                        access_expires_at: time()?,
                    },
                    "access-expired" => State::AccessExpired,
                    "expired" => State::Expired,
                    "cancelled" => State::Cancelled,
                    "revoked" => State::Revoked,
                    _ => return Err(Error::Storage),
                },
                created_at: u64::try_from(created).map_err(bad)?,
            });
        }
        Ok((stopped, saved))
    }

    /// Replace what is stored with this picture, all or nothing.
    pub fn save(&mut self, stopped: bool, saved: &[Saved]) -> Result<(), Error> {
        let int = |n: u64| i64::try_from(n).map_err(bad);
        let tx = self.conn.transaction().map_err(bad)?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('stopped', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![if stopped { "yes" } else { "no" }],
        )
        .map_err(bad)?;
        tx.execute("DELETE FROM requests", []).map_err(bad)?;
        for s in saved {
            let (state, time) = match s.state {
                State::Pending { expires_at } => ("pending", Some(expires_at)),
                State::Delayed { ready_at } => ("delayed", Some(ready_at)),
                State::Ready { expires_at } => ("ready", Some(expires_at)),
                State::Delivered { access_expires_at } => ("delivered", Some(access_expires_at)),
                State::AccessExpired => ("access-expired", None),
                State::Expired => ("expired", None),
                State::Cancelled => ("cancelled", None),
                State::Revoked => ("revoked", None),
            };
            let pin_kind = s.spec.pin.as_ref().map(|p| match p.kind() {
                PinKind::Commit => "commit",
                PinKind::Digest => "digest",
            });
            tx.execute(
                "INSERT INTO requests VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    s.id.as_str(),
                    s.agent.as_str(),
                    s.spec.customer.as_str(),
                    s.spec.system.as_str(),
                    s.spec.action.as_str(),
                    s.spec.target.as_str(),
                    pin_kind,
                    s.spec.pin.as_ref().map(Pin::as_str),
                    s.reason.as_str(),
                    match s.level {
                        Level::One => 1,
                        Level::Two => 2,
                        Level::Three => 3,
                    },
                    int(s.ttl_secs)?,
                    s.first_approver.as_ref().map(CredentialId::as_str),
                    state,
                    time.map(int).transpose()?,
                    int(s.created_at)?,
                ],
            )
            .map_err(bad)?;
        }
        tx.commit().map_err(bad)
    }

    /// A small named value, such as which GitHub installations Key-Box suspended.
    pub fn meta(&self, key: &str) -> Result<Option<String>, Error> {
        let mut statement = self
            .conn
            .prepare("SELECT value FROM meta WHERE key = ?1")
            .map_err(bad)?;
        let mut rows = statement.query(params![key]).map_err(bad)?;
        match rows.next().map_err(bad)? {
            Some(row) => Ok(Some(row.get(0).map_err(bad)?)),
            None => Ok(None),
        }
    }

    pub fn set_meta(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(bad)
    }

    /// The approved policy: file names and their text.
    pub fn policy_files(&self) -> Result<Vec<(String, String)>, Error> {
        let mut statement = self
            .conn
            .prepare("SELECT name, content FROM policy_files ORDER BY name")
            .map_err(bad)?;
        let rows = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(bad)?;
        rows.collect::<Result<_, _>>().map_err(bad)
    }

    /// Replace the approved policy, all or nothing.
    pub fn set_policy_files(&mut self, files: &[(String, String)]) -> Result<(), Error> {
        let tx = self.conn.transaction().map_err(bad)?;
        tx.execute("DELETE FROM policy_files", []).map_err(bad)?;
        for (name, content) in files {
            tx.execute(
                "INSERT INTO policy_files VALUES (?1, ?2)",
                params![name, content],
            )
            .map_err(bad)?;
        }
        tx.commit().map_err(bad)
    }
}
