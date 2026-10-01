//! Community membership composition over the cvld leaves.
//!
//! This is a trusted service API, not an HTTP authorization boundary. See
//! `docs/CONTRACT.md` for authenticated inputs, coordination and recovery.
#![forbid(unsafe_code)]

mod membership;
mod pins;
pub use pins::PinV2;
mod storage;

pub use membership::{
    Config, Lobby, Login, Membership, PendingAdditionalRegistration, PendingLogin,
    PendingRegistration, Warning,
};
pub use storage::{LibsqlStorage, MemoryStorage, Revocation, SCHEMA, Storage};
// Export protocol values only; callers cannot reach leaf writers through cmbr.
pub use cnrl::{Record, State};
pub use ckyh::{Authentication, Uuid};
pub use cpns::server::Pin;
pub use crgs::{Handle, Member, YearMonth};

/// Append these schemas, in this order, to the service's complete migration list.
/// The root assigns contiguous versions; leaves never migrate independently.
pub const SCHEMAS: [(&str, &str); 6] = [
    ("cmbr", SCHEMA),
    ("ckyh", ckyh::LIBSQL_SCHEMA),
    ("crgs", crgs::SCHEMA),
    ("cnrl", cnrl::SCHEMA),
    ("cpns", cpns::server::libsql::SCHEMA),
    ("clbs", clbs::SCHEMA),
];

/// A sanitized facade failure; no underlying request or database error is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid configuration, clock or command.
    #[error("invalid membership input")]
    InvalidInput,
    /// Community, user or pseudonym binding did not match.
    #[error("membership identity mismatch")]
    Identity,
    /// A lifecycle step is unavailable or the row is missing.
    #[error("membership transition refused")]
    Transition,
    /// A leaf refused a register operation.
    #[error("register operation refused")]
    Register,
    /// WebAuthn verification, ownership or counter validation failed.
    #[error("passkey operation refused")]
    Passkey,
    /// The rulebook did not authorize admission or lapse.
    #[error("membership policy refused")]
    Policy,
    /// An applicable legal restriction prevents the action.
    #[error("membership is restricted")]
    Restricted,
    /// Pin creation or its spent change authorization was refused.
    #[error("pin operation refused")]
    Pin,
    /// The private change-token extension circuit has not been proven.
    #[error("pin changes unavailable: extension proofs are not enabled")]
    ExtensionsUnavailable,
    /// Another writer changed the same member row.
    #[error("membership revision conflict; retry with current state")]
    Busy,
    /// Storage, task execution or verification infrastructure failed.
    #[error("membership unavailable")]
    Unavailable,
}

/// Result without sensitive error context.
pub type Result<T> = std::result::Result<T, Error>;

impl From<crlt::Error> for Error {
    fn from(_: crlt::Error) -> Self {
        Self::Unavailable
    }
}
impl From<cnrl::Error> for Error {
    fn from(e: cnrl::Error) -> Self {
        match e {
            cnrl::Error::Storage => Self::Unavailable,
            cnrl::Error::Scope => Self::Identity,
            _ => Self::Transition,
        }
    }
}
impl From<crgs::Error> for Error {
    fn from(e: crgs::Error) -> Self {
        match e {
            crgs::Error::Storage => Self::Unavailable,
            _ => Self::Register,
        }
    }
}
impl From<ckyh::Error> for Error {
    fn from(e: ckyh::Error) -> Self {
        match e {
            ckyh::Error::Storage => Self::Unavailable,
            _ => Self::Passkey,
        }
    }
}
impl From<cpns::server::Error> for Error {
    fn from(e: cpns::server::Error) -> Self {
        match e {
            cpns::server::Error::Storage => Self::Unavailable,
            _ => Self::Pin,
        }
    }
}
impl From<clbs::Error> for Error {
    fn from(error: clbs::Error) -> Self {
        match error {
            clbs::Error::Storage | clbs::Error::Clock => Self::Unavailable,
            clbs::Error::CommunityMismatch => Self::Identity,
            _ => Self::Restricted,
        }
    }
}

pub(crate) fn text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

#[cfg(test)]
extern crate self as cmbr;
