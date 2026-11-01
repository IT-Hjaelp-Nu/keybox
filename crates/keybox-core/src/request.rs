//! What an agent asks for, and the bytes an approval is bound to.

use crate::ident::{ActionId, CustomerId, InvalidIdent, Pin, PinKind, RequestId, SystemId, Target};
use crate::policy::Level;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSpec {
    pub customer: CustomerId,
    pub system: SystemId,
    pub action: ActionId,
    pub target: Target,
    pub pin: Option<Pin>,
}

impl RequestSpec {
    /// The canonical bytes a passkey approval covers. Every field is length
    /// prefixed, so two different requests can never encode to the same bytes.
    pub fn binding(&self, id: &RequestId, level: Level) -> Vec<u8> {
        fn put(buf: &mut Vec<u8>, field: &str) {
            // Every field is at most 200 bytes by construction.
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field.as_bytes());
        }
        let mut buf = b"keybox-binding-v1\0".to_vec();
        put(&mut buf, id.as_str());
        buf.push(match level {
            Level::One => 1,
            Level::Two => 2,
            Level::Three => 3,
        });
        put(&mut buf, self.customer.as_str());
        put(&mut buf, self.system.as_str());
        put(&mut buf, self.action.as_str());
        put(&mut buf, self.target.as_str());
        match &self.pin {
            None => buf.push(0),
            Some(pin) => {
                buf.push(match pin.kind() {
                    PinKind::Commit => 1,
                    PinKind::Digest => 2,
                });
                put(&mut buf, pin.as_str());
            }
        }
        buf
    }
}

/// Free text written by the agent. Untrusted: shown escaped and labelled, and
/// never part of any decision. At most 500 characters, no control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(String);

impl Reason {
    pub fn new(s: &str) -> Result<Self, InvalidIdent> {
        if s.chars().count() <= 500 && !s.chars().any(char::is_control) {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidIdent("reason"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
