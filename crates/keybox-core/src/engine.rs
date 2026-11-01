//! The request state machine.
//!
//! Time is passed in as Unix seconds so every rule can be tested exactly. The
//! engine trusts its caller on three points only: that `agent` is who the
//! socket peer really is, that `approve` is called only after a passkey
//! assertion over `binding` has been verified, and that `now` is the clock.

use std::collections::BTreeMap;

use crate::ident::{AgentId, CredentialId, RequestId};
use crate::policy::{Deny, Level, Policy};
use crate::request::{Reason, RequestSpec};

/// How long a request waits for a passkey before it expires.
pub const APPROVAL_WINDOW_SECS: u64 = 300;
/// How long an approved access waits to be fetched before it expires.
pub const FETCH_WINDOW_SECS: u64 = 300;
/// The cancellable wait after a single passkey on level 3.
pub const LEVEL3_DELAY_SECS: u64 = 600;
/// Open requests one agent may have at a time, so it cannot bury the approval page.
pub const MAX_OPEN_PER_AGENT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for a passkey.
    Pending {
        expires_at: u64,
    },
    /// Level 3, one passkey given: waiting out the delay.
    Delayed {
        ready_at: u64,
    },
    /// May be fetched once.
    Ready {
        expires_at: u64,
    },
    /// Handed out. The access itself is not kept.
    Delivered {
        access_expires_at: u64,
    },
    AccessExpired,
    Expired,
    Cancelled,
    Revoked,
}

impl State {
    fn is_open(self) -> bool {
        matches!(
            self,
            State::Pending { .. } | State::Delayed { .. } | State::Ready { .. }
        )
    }
}

/// Why a call was refused. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Emergency stop is active.
    Stopped,
    Policy(Deny),
    TooManyOpen,
    DuplicateId,
    /// No such request, or it belongs to another agent.
    UnknownRequest,
    NotApproved,
    DelayNotElapsed,
    AlreadyApproved,
    /// The approval was made for a different request.
    BindingMismatch,
    /// Level 3 needs a second, different passkey to skip the delay.
    SameCredential,
    /// Delivered, expired, cancelled or revoked.
    Closed,
}

impl Refusal {
    /// A fixed word for the log and for the answer to the agent.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Stopped => "stopped",
            Refusal::TooManyOpen => "too-many-open",
            Refusal::DuplicateId => "duplicate-id",
            Refusal::UnknownRequest => "unknown-request",
            Refusal::NotApproved => "not-approved",
            Refusal::DelayNotElapsed => "delay-not-elapsed",
            Refusal::AlreadyApproved => "already-approved",
            Refusal::BindingMismatch => "binding-mismatch",
            Refusal::SameCredential => "same-credential",
            Refusal::Closed => "closed",
            Refusal::Policy(deny) => match deny {
                Deny::UnknownCustomer => "policy:unknown-customer",
                Deny::UnknownSystem => "policy:unknown-system",
                Deny::UnknownAction => "policy:unknown-action",
                Deny::AgentNotAllowed => "policy:agent-not-allowed",
                Deny::TargetNotAllowed => "policy:target-not-allowed",
                Deny::PinRequired => "policy:pin-required",
                Deny::PinNotAllowed => "policy:pin-not-allowed",
                Deny::PinWrongKind => "policy:pin-wrong-kind",
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    Requested {
        spec: RequestSpec,
        level: Level,
        reason: Reason,
    },
    Approved {
        credential: CredentialId,
    },
    Delayed {
        ready_at: u64,
    },
    Ready,
    Delivered {
        access_expires_at: u64,
    },
    Cancelled,
    Withdrawn,
    Expired,
    AccessExpired,
    Revoked,
    EmergencyStop,
    Resumed,
    Refused(Refusal),
}

/// One line for the audit log. Built only from validated identifiers and
/// times, so it can be written out as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub at: u64,
    pub request: Option<RequestId>,
    pub agent: Option<AgentId>,
    pub kind: EventKind,
}

/// What the daemon must issue after a successful fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub spec: RequestSpec,
    pub ttl_secs: u64,
    pub access_expires_at: u64,
}

/// A request shown on the approval page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Awaiting {
    pub id: RequestId,
    pub agent: AgentId,
    pub spec: RequestSpec,
    pub reason: Reason,
    pub level: Level,
    pub state: State,
}

struct Entry {
    agent: AgentId,
    spec: RequestSpec,
    reason: Reason,
    level: Level,
    ttl_secs: u64,
    binding: Vec<u8>,
    first_approver: Option<CredentialId>,
    state: State,
    created_at: u64,
}

/// One request as it is written to disk and read back. The binding is not
/// stored: it is recomputed from the fields, so it cannot drift from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub id: RequestId,
    pub agent: AgentId,
    pub spec: RequestSpec,
    pub reason: Reason,
    pub level: Level,
    pub ttl_secs: u64,
    pub first_approver: Option<CredentialId>,
    pub state: State,
    pub created_at: u64,
}

/// How long a closed request is remembered, so a late `status` or `fetch`
/// still gets a clear answer. Far longer than any request can stay open.
pub const KEEP_CLOSED_SECS: u64 = 24 * 60 * 60;

pub struct Engine {
    policy: Policy,
    entries: BTreeMap<RequestId, Entry>,
    stopped: bool,
    events: Vec<Event>,
}

impl Engine {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            entries: BTreeMap::new(),
            stopped: false,
            events: Vec::new(),
        }
    }

    /// Everything that must survive a restart: whether the emergency stop is
    /// on, and every request still remembered.
    pub fn snapshot(&self) -> (bool, Vec<Saved>) {
        let saved = self
            .entries
            .iter()
            .map(|(id, e)| Saved {
                id: id.clone(),
                agent: e.agent.clone(),
                spec: e.spec.clone(),
                reason: e.reason.clone(),
                level: e.level,
                ttl_secs: e.ttl_secs,
                first_approver: e.first_approver.clone(),
                state: e.state,
                created_at: e.created_at,
            })
            .collect();
        (self.stopped, saved)
    }

    /// Start again from a snapshot. An open request that the policy no longer
    /// allows, or now places on another level, is revoked: an approval given
    /// under one policy is not carried into another.
    pub fn restore(policy: Policy, stopped: bool, saved: Vec<Saved>, now: u64) -> Self {
        let mut engine = Self::new(policy);
        engine.stopped = stopped;
        for s in saved {
            let mut state = s.state;
            if state.is_open() {
                let still_allowed = engine
                    .policy
                    .check(&s.agent, &s.spec)
                    .is_ok_and(|rule| rule.level == s.level && rule.ttl_secs == s.ttl_secs);
                if stopped || !still_allowed {
                    state = State::Revoked;
                    engine.events.push(Event {
                        at: now,
                        request: Some(s.id.clone()),
                        agent: Some(s.agent.clone()),
                        kind: EventKind::Revoked,
                    });
                }
            }
            let binding = s.spec.binding(&s.id, s.level);
            engine.entries.insert(
                s.id,
                Entry {
                    agent: s.agent,
                    spec: s.spec,
                    reason: s.reason,
                    level: s.level,
                    ttl_secs: s.ttl_secs,
                    binding,
                    first_approver: s.first_approver,
                    state,
                    created_at: s.created_at,
                },
            );
        }
        engine.tick(now);
        engine
    }

    /// The policy in force.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Events since the last call, oldest first.
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// What `agent`'s own request `id` asks for. `None` for anyone else's.
    pub fn spec(&self, agent: &AgentId, id: &RequestId) -> Option<&RequestSpec> {
        self.entries
            .get(id)
            .filter(|e| &e.agent == agent)
            .map(|e| &e.spec)
    }

    /// The bytes an approval of `id` must cover.
    pub fn binding(&self, id: &RequestId) -> Option<&[u8]> {
        self.entries.get(id).map(|e| e.binding.as_slice())
    }

    /// An agent asks for an access.
    pub fn submit(
        &mut self,
        now: u64,
        agent: &AgentId,
        id: RequestId,
        spec: RequestSpec,
        reason: Reason,
    ) -> Result<State, Refusal> {
        self.tick(now);
        let checked = if self.stopped {
            Err(Refusal::Stopped)
        } else if self.entries.contains_key(&id) {
            Err(Refusal::DuplicateId)
        } else {
            match self.policy.check(agent, &spec) {
                Err(deny) => Err(Refusal::Policy(deny)),
                Ok(_) if self.open_count(agent) >= MAX_OPEN_PER_AGENT => Err(Refusal::TooManyOpen),
                Ok(rule) => Ok((rule.level, rule.ttl_secs)),
            }
        };
        let (level, ttl_secs) = match checked {
            Ok(v) => v,
            // The id is the caller's own for a rejected submit; never another entry's.
            Err(r) => return Err(self.refuse(now, None, Some(agent), r)),
        };
        let state = match level {
            Level::One => State::Ready {
                expires_at: now.saturating_add(FETCH_WINDOW_SECS),
            },
            Level::Two | Level::Three => State::Pending {
                expires_at: now.saturating_add(APPROVAL_WINDOW_SECS),
            },
        };
        self.log(
            now,
            &id,
            Some(agent),
            EventKind::Requested {
                spec: spec.clone(),
                level,
                reason: reason.clone(),
            },
        );
        if level == Level::One {
            self.log(now, &id, Some(agent), EventKind::Ready);
        }
        let binding = spec.binding(&id, level);
        self.entries.insert(
            id,
            Entry {
                agent: agent.clone(),
                spec,
                reason,
                level,
                ttl_secs,
                binding,
                first_approver: None,
                state,
                created_at: now,
            },
        );
        Ok(state)
    }

    /// Christian approved `binding` with the passkey `credential`.
    pub fn approve(
        &mut self,
        now: u64,
        id: &RequestId,
        binding: &[u8],
        credential: &CredentialId,
    ) -> Result<State, Refusal> {
        self.tick(now);
        let decided = if self.stopped {
            Err(Refusal::Stopped)
        } else {
            match self.entries.get(id) {
                None => Err(Refusal::UnknownRequest),
                Some(e) if !e.state.is_open() => Err(Refusal::Closed),
                Some(e) if e.binding != binding => Err(Refusal::BindingMismatch),
                Some(e) => match (e.state, e.level) {
                    (State::Pending { .. }, Level::Three) => Ok(State::Delayed {
                        ready_at: now.saturating_add(LEVEL3_DELAY_SECS),
                    }),
                    (State::Pending { .. }, _) => Ok(State::Ready {
                        expires_at: now.saturating_add(FETCH_WINDOW_SECS),
                    }),
                    (State::Delayed { .. }, _) if e.first_approver.as_ref() == Some(credential) => {
                        Err(Refusal::SameCredential)
                    }
                    (State::Delayed { .. }, _) => Ok(State::Ready {
                        expires_at: now.saturating_add(FETCH_WINDOW_SECS),
                    }),
                    _ => Err(Refusal::AlreadyApproved),
                },
            }
        };
        let state = match decided {
            Ok(s) => s,
            Err(r) => return Err(self.refuse(now, Some(id), None, r)),
        };
        self.log(
            now,
            id,
            None,
            EventKind::Approved {
                credential: credential.clone(),
            },
        );
        match state {
            State::Delayed { ready_at } => self.log(now, id, None, EventKind::Delayed { ready_at }),
            _ => self.log(now, id, None, EventKind::Ready),
        }
        if let Some(e) = self.entries.get_mut(id) {
            e.first_approver.get_or_insert_with(|| credential.clone());
            e.state = state;
        }
        Ok(state)
    }

    /// Christian rejects a request or cancels a level-3 delay. Allowed during
    /// an emergency stop: it can only close things.
    pub fn cancel(&mut self, now: u64, id: &RequestId) -> Result<(), Refusal> {
        self.tick(now);
        self.close(now, id, None, EventKind::Cancelled)
    }

    /// The agent gives up its own request.
    pub fn withdraw(&mut self, now: u64, agent: &AgentId, id: &RequestId) -> Result<(), Refusal> {
        self.tick(now);
        self.close(now, id, Some(agent), EventKind::Withdrawn)
    }

    /// The agent's view of its own request.
    pub fn status(&mut self, now: u64, agent: &AgentId, id: &RequestId) -> Result<State, Refusal> {
        self.tick(now);
        match self.entries.get(id) {
            Some(e) if &e.agent == agent => Ok(e.state),
            // Asking about an id that is not yours is worth a line in the log.
            _ => Err(self.refuse(now, Some(id), Some(agent), Refusal::UnknownRequest)),
        }
    }

    /// Hand out the access, once. On `Ok` the daemon issues the credential;
    /// if issuing fails the request stays closed and the agent must ask again.
    pub fn fetch(
        &mut self,
        now: u64,
        agent: &AgentId,
        id: &RequestId,
    ) -> Result<Delivery, Refusal> {
        self.tick(now);
        let decided = if self.stopped {
            Err(Refusal::Stopped)
        } else {
            match self.entries.get(id) {
                Some(e) if &e.agent == agent => match e.state {
                    State::Ready { .. } => Ok(Delivery {
                        spec: e.spec.clone(),
                        ttl_secs: e.ttl_secs,
                        access_expires_at: now.saturating_add(e.ttl_secs),
                    }),
                    State::Pending { .. } => Err(Refusal::NotApproved),
                    State::Delayed { .. } => Err(Refusal::DelayNotElapsed),
                    _ => Err(Refusal::Closed),
                },
                _ => Err(Refusal::UnknownRequest),
            }
        };
        let delivery = match decided {
            Ok(d) => d,
            Err(r) => return Err(self.refuse(now, Some(id), Some(agent), r)),
        };
        let access_expires_at = delivery.access_expires_at;
        if let Some(e) = self.entries.get_mut(id) {
            e.state = State::Delivered { access_expires_at };
        }
        self.log(
            now,
            id,
            Some(agent),
            EventKind::Delivered { access_expires_at },
        );
        Ok(delivery)
    }

    /// Requests waiting for Christian: unapproved ones and level-3 delays.
    pub fn awaiting_approval(&mut self, now: u64) -> Vec<Awaiting> {
        self.tick(now);
        self.entries
            .iter()
            .filter(|(_, e)| matches!(e.state, State::Pending { .. } | State::Delayed { .. }))
            .map(|(id, e)| Awaiting {
                id: id.clone(),
                agent: e.agent.clone(),
                spec: e.spec.clone(),
                reason: e.reason.clone(),
                level: e.level,
                state: e.state,
            })
            .collect()
    }

    /// Revoke everything and refuse everything until [`Engine::resume`].
    /// Returns the delivered accesses that are still valid, for the issuers
    /// to revoke where they can.
    pub fn emergency_stop(&mut self, now: u64) -> Vec<(RequestId, RequestSpec)> {
        self.tick(now);
        self.stopped = true;
        self.events.push(Event {
            at: now,
            request: None,
            agent: None,
            kind: EventKind::EmergencyStop,
        });
        let mut live = Vec::new();
        for (id, e) in &mut self.entries {
            if matches!(e.state, State::Delivered { .. }) {
                live.push((id.clone(), e.spec.clone()));
            } else if !e.state.is_open() {
                continue;
            }
            e.state = State::Revoked;
            self.events.push(Event {
                at: now,
                request: Some(id.clone()),
                agent: Some(e.agent.clone()),
                kind: EventKind::Revoked,
            });
        }
        live
    }

    /// Turn Key-Box back on. The daemon requires a passkey for this.
    pub fn resume(&mut self, now: u64) {
        self.stopped = false;
        self.events.push(Event {
            at: now,
            request: None,
            agent: None,
            kind: EventKind::Resumed,
        });
    }

    fn close(
        &mut self,
        now: u64,
        id: &RequestId,
        owner: Option<&AgentId>,
        kind: EventKind,
    ) -> Result<(), Refusal> {
        let refusal = match self.entries.get_mut(id) {
            Some(e) if owner.is_none_or(|a| a == &e.agent) => {
                if e.state.is_open() {
                    e.state = State::Cancelled;
                    self.log(now, id, owner, kind);
                    return Ok(());
                }
                Refusal::Closed
            }
            _ => Refusal::UnknownRequest,
        };
        Err(self.refuse(now, Some(id), owner, refusal))
    }

    fn open_count(&self, agent: &AgentId) -> usize {
        self.entries
            .values()
            .filter(|e| &e.agent == agent && e.state.is_open())
            .count()
    }

    fn log(&mut self, at: u64, id: &RequestId, agent: Option<&AgentId>, kind: EventKind) {
        self.events.push(Event {
            at,
            request: Some(id.clone()),
            agent: agent.cloned(),
            kind,
        });
    }

    fn refuse(
        &mut self,
        at: u64,
        id: Option<&RequestId>,
        agent: Option<&AgentId>,
        refusal: Refusal,
    ) -> Refusal {
        self.events.push(Event {
            at,
            request: id.cloned(),
            agent: agent.cloned(),
            kind: EventKind::Refused(refusal),
        });
        refusal
    }

    /// Apply everything that has happened purely because time passed.
    fn tick(&mut self, now: u64) {
        // Forget requests that were closed long ago.
        self.entries.retain(|_, e| {
            e.state.is_open()
                || matches!(e.state, State::Delivered { .. })
                || now < e.created_at.saturating_add(KEEP_CLOSED_SECS)
        });
        for (id, e) in &mut self.entries {
            loop {
                let (next, at, kind) = match e.state {
                    State::Pending { expires_at } | State::Ready { expires_at }
                        if now >= expires_at =>
                    {
                        (State::Expired, expires_at, EventKind::Expired)
                    }
                    State::Delayed { ready_at } if now >= ready_at => (
                        State::Ready {
                            expires_at: ready_at.saturating_add(FETCH_WINDOW_SECS),
                        },
                        ready_at,
                        EventKind::Ready,
                    ),
                    State::Delivered { access_expires_at } if now >= access_expires_at => (
                        State::AccessExpired,
                        access_expires_at,
                        EventKind::AccessExpired,
                    ),
                    _ => break,
                };
                e.state = next;
                self.events.push(Event {
                    at,
                    request: Some(id.clone()),
                    agent: Some(e.agent.clone()),
                    kind,
                });
            }
        }
    }
}
