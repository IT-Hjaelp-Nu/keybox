//! Key-Box core: what may be requested, when it counts as approved, and when
//! it may be handed out.
//!
//! This crate has no dependencies, does no I/O and never holds a secret. The
//! daemon around it authenticates callers, verifies passkeys and issues
//! credentials; every security decision is taken here.

#![forbid(unsafe_code)]

pub mod engine;
pub mod ident;
pub mod policy;
pub mod request;
