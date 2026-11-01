//! The audit log: one line per event, each carrying the hash of the line
//! before it.
//!
//! A line is `<hash> <prev> <body>\n`, where `body` is one JSON object and
//! `hash = SHA-256(prev ‖ "\n" ‖ body)` over the bytes exactly as written.
//! Changing, removing, reordering or inserting a line breaks the chain from
//! that line on. Removing lines from the *end* does not; that shows only as a
//! different [`Head`], which is why the head is meant to be kept elsewhere too.
//!
//! The file is opened append-only, so the administrator can also set the
//! append-only attribute (`chattr +a`) and have the kernel enforce it.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use keybox_core::engine::{Event, EventKind};
use keybox_core::ident::{AgentId, CredentialId, PinKind, RequestId, SecretName};
use keybox_core::policy::Level;
use keybox_core::request::{Reason, RequestSpec};
use ring::digest::{SHA256, digest};
use serde_json::{Map, Value};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The newest line: how many there are, and the hash of the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogError {
    /// The chain does not hold at this line (1-based).
    Broken {
        line: u64,
    },
    /// Another process has the log open for writing.
    Locked,
    Io(io::ErrorKind),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::Broken { line } => write!(f, "audit log: chain is broken at line {line}"),
            LogError::Locked => write!(f, "audit log: already open in another process"),
            LogError::Io(kind) => write!(f, "audit log: {kind}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<io::Error> for LogError {
    fn from(e: io::Error) -> Self {
        LogError::Io(e.kind())
    }
}

/// A value that may be written to the log. There is deliberately no
/// conversion from `String` or `&str`: only validated identifiers, numbers,
/// fixed words and the agent's bounded free text can get in, so a secret
/// cannot be logged by passing the wrong variable.
pub struct Field(Value);

impl From<u64> for Field {
    fn from(n: u64) -> Self {
        Field(n.into())
    }
}

impl Field {
    /// A hash, written as hexadecimal. Any 32 bytes are safe to log this way.
    pub fn hex(bytes: &[u8; 32]) -> Self {
        Field(
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .into(),
        )
    }
}

macro_rules! field_from_str_type {
    ($($t:ty),*) => {$(
        impl From<&$t> for Field {
            fn from(v: &$t) -> Self {
                Field(v.as_str().into())
            }
        }
    )*};
}

field_from_str_type!(AgentId, CredentialId, RequestId, SecretName, Reason);

/// One line to be logged.
pub struct Record {
    body: Map<String, Value>,
}

impl Record {
    /// `kind` is a fixed word chosen in the code, never input.
    pub fn new(at: u64, kind: &'static str) -> Self {
        let mut body = Map::new();
        body.insert("at".into(), at.into());
        body.insert("kind".into(), kind.into());
        Self { body }
    }

    pub fn with(mut self, key: &'static str, value: impl Into<Field>) -> Self {
        self.body.insert(key.into(), value.into().0);
        self
    }

    /// A fixed word chosen in the code, never input.
    pub fn word(mut self, key: &'static str, word: &'static str) -> Self {
        self.body.insert(key.into(), word.into());
        self
    }

    fn spec(mut self, spec: &RequestSpec) -> Self {
        let mut put = |k: &str, v: &str| self.body.insert(k.into(), v.into());
        put("customer", spec.customer.as_str());
        put("system", spec.system.as_str());
        put("action", spec.action.as_str());
        put("target", spec.target.as_str());
        if let Some(pin) = &spec.pin {
            let key = match pin.kind() {
                PinKind::Commit => "commit",
                PinKind::Digest => "digest",
            };
            put(key, pin.as_str());
        }
        self
    }
}

impl From<&Event> for Record {
    fn from(event: &Event) -> Self {
        let kind = match &event.kind {
            EventKind::Requested { .. } => "requested",
            EventKind::Approved { .. } => "approved",
            EventKind::Delayed { .. } => "delayed",
            EventKind::Ready => "ready",
            EventKind::Delivered { .. } => "delivered",
            EventKind::Cancelled => "cancelled",
            EventKind::Withdrawn => "withdrawn",
            EventKind::Expired => "expired",
            EventKind::AccessExpired => "access-expired",
            EventKind::Revoked => "revoked",
            EventKind::EmergencyStop => "emergency-stop",
            EventKind::Resumed => "resumed",
            EventKind::Refused(_) => "refused",
        };
        let mut record = Record::new(event.at, kind);
        if let Some(id) = &event.request {
            record = record.with("request", id);
        }
        if let Some(agent) = &event.agent {
            record = record.with("agent", agent);
        }
        match &event.kind {
            EventKind::Requested {
                spec,
                level,
                reason,
            } => {
                let level = match level {
                    Level::One => 1,
                    Level::Two => 2,
                    Level::Three => 3,
                };
                record
                    .spec(spec)
                    .with("level", level)
                    .with("reason", reason)
            }
            EventKind::Approved { credential } => record.with("credential", credential),
            EventKind::Delayed { ready_at } => record.with("ready_at", *ready_at),
            EventKind::Delivered { access_expires_at } => {
                record.with("access_expires_at", *access_expires_at)
            }
            EventKind::Refused(refusal) => record.word("why", refusal.code()),
            _ => record,
        }
    }
}

impl From<Event> for Record {
    fn from(event: Event) -> Self {
        (&event).into()
    }
}

fn hash_line(prev: &str, body: &str) -> String {
    let mut input = Vec::with_capacity(prev.len() + 1 + body.len());
    input.extend_from_slice(prev.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(body.as_bytes());
    digest(&SHA256, &input)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Walk the whole chain. Returns the head, or the first line that does not fit.
pub fn verify(path: &Path) -> Result<Head, LogError> {
    verify_reader(BufReader::new(File::open(path)?))
}

fn verify_reader(mut reader: impl BufRead) -> Result<Head, LogError> {
    let mut head = Head {
        seq: 0,
        hash: GENESIS.to_owned(),
    };
    let mut raw = Vec::new();
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            return Ok(head);
        }
        let line = head.seq + 1;
        let broken = LogError::Broken { line };
        // A line without its newline was cut off mid-write.
        let text = raw
            .strip_suffix(b"\n")
            .and_then(|l| std::str::from_utf8(l).ok());
        let mut parts = text.ok_or(LogError::Broken { line })?.splitn(3, ' ');
        let (Some(hash), Some(prev), Some(body)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(broken);
        };
        if prev != head.hash || hash != hash_line(prev, body) {
            return Err(broken);
        }
        head = Head {
            seq: line,
            hash: hash.to_owned(),
        };
    }
}

/// The log, open for appending. Holds an exclusive lock on the file.
pub struct AuditLog {
    file: File,
    head: Head,
}

impl AuditLog {
    /// Open or create the log. Verifies the whole chain first and refuses a
    /// log that does not verify: Key-Box must not run on top of a history it
    /// cannot vouch for.
    pub fn open(path: &Path) -> Result<Self, LogError> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LogError::Locked),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let head = verify_reader(BufReader::new(&file))?;
        Ok(Self { file, head })
    }

    pub fn head(&self) -> Head {
        self.head.clone()
    }

    /// Write one line and wait until it is on disk. The caller must not act
    /// on the event (hand out an access, answer the agent) before this returns.
    pub fn append(&mut self, record: &Record) -> Result<(), LogError> {
        let seq = self.head.seq + 1;
        let mut body = Map::new();
        body.insert("seq".into(), seq.into());
        body.extend(record.body.clone());
        // serde_json escapes every control character, so the body is one line.
        let body = Value::Object(body).to_string();
        let hash = hash_line(&self.head.hash, &body);
        let line = format!("{hash} {} {body}\n", self.head.hash);
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        self.head = Head { seq, hash };
        Ok(())
    }
}
