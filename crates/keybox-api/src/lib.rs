//! The agent API: one JSON line in, one JSON line out.
//!
//! This crate knows nothing about sockets or TLS. The transport hands it the
//! line it read and the agent it authenticated; everything an agent can say
//! to Key-Box is defined, parsed and dispatched here.
//!
//! An agent can ask, look, fetch and withdraw. It cannot approve.

#![forbid(unsafe_code)]

use std::fmt;

use keybox_core::engine::{Delivery, Engine, Refusal, State};
use keybox_core::ident::{
    ActionId, AgentId, CustomerId, InvalidIdent, Pin, PinKind, RequestId, SshPublicKey, SystemId,
    Target,
};
use keybox_core::policy::Level;
use keybox_core::request::{Reason, RequestSpec};
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Longest line an agent may send, newline excluded.
pub const MAX_LINE_BYTES: usize = 4096;

/// Why a line was not understood. Never carries any part of the line: what
/// an agent sends may be attacker text, or a secret pasted into the wrong field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    TooLarge,
    /// Not one JSON object of a known shape.
    Malformed,
    /// A field is outside its grammar.
    Invalid(InvalidIdent),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::TooLarge => f.write_str("too-large"),
            ApiError::Malformed => f.write_str("malformed"),
            ApiError::Invalid(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<InvalidIdent> for ApiError {
    fn from(e: InvalidIdent) -> Self {
        ApiError::Invalid(e)
    }
}

/// A fully validated call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Request {
        spec: RequestSpec,
        reason: Reason,
    },
    Status {
        id: RequestId,
    },
    /// `public_key` is needed when the access is an SSH certificate.
    Fetch {
        id: RequestId,
        public_key: Option<SshPublicKey>,
    },
    Withdraw {
        id: RequestId,
    },
    /// What this agent may ask for at all.
    List,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Wire {
    Request {
        customer: String,
        system: String,
        action: String,
        target: String,
        commit: Option<String>,
        digest: Option<String>,
        reason: String,
    },
    Status {
        id: String,
    },
    Fetch {
        id: String,
        public_key: Option<String>,
    },
    Withdraw {
        id: String,
    },
    List {},
}

/// Parse one line. Unknown fields, missing fields, repeated fields and
/// anything after the object are errors.
pub fn parse(line: &[u8]) -> Result<Call, ApiError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ApiError::TooLarge);
    }
    let wire: Wire = serde_json::from_slice(line).map_err(|_| ApiError::Malformed)?;
    Ok(match wire {
        Wire::Request {
            customer,
            system,
            action,
            target,
            commit,
            digest,
            reason,
        } => {
            let pin = match (commit, digest) {
                (None, None) => None,
                (Some(c), None) => Some(Pin::commit(&c)?),
                (None, Some(d)) => Some(Pin::digest(&d)?),
                (Some(_), Some(_)) => return Err(ApiError::Malformed),
            };
            Call::Request {
                spec: RequestSpec {
                    customer: CustomerId::new(&customer)?,
                    system: SystemId::new(&system)?,
                    action: ActionId::new(&action)?,
                    target: Target::new(&target)?,
                    pin,
                },
                reason: Reason::new(&reason)?,
            }
        }
        Wire::Status { id } => Call::Status {
            id: RequestId::new(&id)?,
        },
        Wire::Fetch { id, public_key } => Call::Fetch {
            id: RequestId::new(&id)?,
            public_key: public_key.map(|k| SshPublicKey::new(&k)).transpose()?,
        },
        Wire::Withdraw { id } => Call::Withdraw {
            id: RequestId::new(&id)?,
        },
        Wire::List {} => Call::List,
    })
}

/// What the transport does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Send this line back.
    Reply(String),
    /// The engine released the access for `id`. The daemon issues it and
    /// answers the agent itself, so the secret never passes through here.
    Issue {
        id: RequestId,
        delivery: Delivery,
        /// The key to certify, if the agent sent one.
        public_key: Option<SshPublicKey>,
    },
}

/// Handle one line from `agent`: [`parse`], then [`dispatch`].
pub fn handle(
    engine: &mut Engine,
    now: u64,
    agent: &AgentId,
    new_id: RequestId,
    line: &[u8],
) -> Outcome {
    match parse(line) {
        Ok(call) => dispatch(engine, now, agent, new_id, call),
        Err(e) => Outcome::Reply(error_line(&e.to_string())),
    }
}

/// Carry out a parsed call. `new_id` is a fresh random id from the daemon,
/// used only if the call is a new request.
pub fn dispatch(
    engine: &mut Engine,
    now: u64,
    agent: &AgentId,
    new_id: RequestId,
    call: Call,
) -> Outcome {
    let result = match call {
        Call::Request { spec, reason } => engine
            .submit(now, agent, new_id.clone(), spec, reason)
            .map(|state| state_line(&new_id, state)),
        Call::Status { id } => engine
            .status(now, agent, &id)
            .map(|state| state_line(&id, state)),
        Call::Withdraw { id } => engine
            .withdraw(now, agent, &id)
            .map(|()| state_line(&id, State::Cancelled)),
        Call::List => Ok(list_line(engine, agent)),
        Call::Fetch { id, public_key } => match engine.fetch(now, agent, &id) {
            Ok(delivery) => {
                return Outcome::Issue {
                    id,
                    delivery,
                    public_key,
                };
            }
            Err(refusal) => Err(refusal),
        },
    };
    Outcome::Reply(result.unwrap_or_else(|refusal: Refusal| error_line(refusal.code())))
}

/// The actions the policy in force lists this agent for, and nothing about
/// anyone else's. The policy is not a secret, but an agent has no use for
/// the rest of it.
fn list_line(engine: &Engine, agent: &AgentId) -> String {
    let actions: Vec<Value> = engine
        .policy()
        .rules()
        .filter(|(.., rule)| rule.agents.contains(agent))
        .map(|(customer, system, action, rule)| {
            json!({
                "customer": customer.as_str(),
                "system": system.as_str(),
                "action": action.as_str(),
                "targets": rule.targets.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
                "level": match rule.level {
                    Level::One => 1,
                    Level::Two => 2,
                    Level::Three => 3,
                },
                "pin": rule.pin.map(|p| match p {
                    PinKind::Commit => "commit",
                    PinKind::Digest => "digest",
                }),
            })
        })
        .collect();
    json!({ "ok": true, "actions": actions }).to_string()
}

/// `{"ok":false,"error":"<word>"}`. `word` is always a fixed word from the code.
pub fn error_line(word: &str) -> String {
    json!({ "ok": false, "error": word }).to_string()
}

fn state_line(id: &RequestId, state: State) -> String {
    let (word, time) = match state {
        State::Pending { expires_at } => ("pending", Some(("expires_at", expires_at))),
        State::Delayed { ready_at } => ("delayed", Some(("ready_at", ready_at))),
        State::Ready { expires_at } => ("ready", Some(("expires_at", expires_at))),
        State::Delivered { access_expires_at } => {
            ("delivered", Some(("access_expires_at", access_expires_at)))
        }
        State::AccessExpired => ("access-expired", None),
        State::Expired => ("expired", None),
        State::Cancelled => ("cancelled", None),
        State::Revoked => ("revoked", None),
    };
    let mut body = Map::new();
    body.insert("ok".into(), true.into());
    body.insert("id".into(), id.as_str().into());
    body.insert("state".into(), word.into());
    if let Some((key, at)) = time {
        body.insert(key.into(), at.into());
    }
    Value::Object(body).to_string()
}
