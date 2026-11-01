//! The policy: the only things that can be requested at all.

use std::collections::{BTreeMap, BTreeSet};

use crate::ident::{ActionId, AgentId, CustomerId, PinKind, SystemId, Target};
use crate::request::RequestSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// No approval; logged.
    One,
    /// One passkey.
    Two,
    /// One passkey and a cancellable delay, or two different passkeys.
    Three,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRule {
    pub level: Level,
    /// Agents that may request this action.
    pub agents: BTreeSet<AgentId>,
    /// Targets the action may be aimed at. Matched exactly.
    pub targets: BTreeSet<Target>,
    /// Whether the request must name a commit or digest.
    pub pin: Option<PinKind>,
    /// Lifetime of the issued access.
    pub ttl_secs: u64,
}

/// Why the policy said no. Carries no input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    UnknownCustomer,
    UnknownSystem,
    UnknownAction,
    AgentNotAllowed,
    TargetNotAllowed,
    PinRequired,
    PinNotAllowed,
    PinWrongKind,
}

type Systems = BTreeMap<SystemId, BTreeMap<ActionId, ActionRule>>;

/// Customer → system → action → rule. An empty policy allows nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    customers: BTreeMap<CustomerId, Systems>,
}

impl Policy {
    pub fn insert(
        &mut self,
        customer: CustomerId,
        system: SystemId,
        action: ActionId,
        rule: ActionRule,
    ) {
        self.customers
            .entry(customer)
            .or_default()
            .entry(system)
            .or_default()
            .insert(action, rule);
    }

    /// Every rule, in a fixed order.
    pub fn rules(&self) -> impl Iterator<Item = (&CustomerId, &SystemId, &ActionId, &ActionRule)> {
        self.customers.iter().flat_map(|(customer, systems)| {
            systems.iter().flat_map(move |(system, actions)| {
                actions
                    .iter()
                    .map(move |(action, rule)| (customer, system, action, rule))
            })
        })
    }

    /// The rule that allows `spec` for `agent`, or the reason there is none.
    pub fn check(&self, agent: &AgentId, spec: &RequestSpec) -> Result<&ActionRule, Deny> {
        let systems = self
            .customers
            .get(&spec.customer)
            .ok_or(Deny::UnknownCustomer)?;
        let actions = systems.get(&spec.system).ok_or(Deny::UnknownSystem)?;
        let rule = actions.get(&spec.action).ok_or(Deny::UnknownAction)?;
        if !rule.agents.contains(agent) {
            return Err(Deny::AgentNotAllowed);
        }
        if !rule.targets.contains(&spec.target) {
            return Err(Deny::TargetNotAllowed);
        }
        match (rule.pin, &spec.pin) {
            (None, None) => Ok(rule),
            (Some(_), None) => Err(Deny::PinRequired),
            (None, Some(_)) => Err(Deny::PinNotAllowed),
            (Some(want), Some(pin)) if pin.kind() == want => Ok(rule),
            (Some(_), Some(_)) => Err(Deny::PinWrongKind),
        }
    }
}
