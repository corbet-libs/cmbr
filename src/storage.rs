use std::{future::Future, sync::Arc};

use crlt::{Community, params};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{Error, Result};

/// Append to the composition root's ordered crlt migration history.
pub const SCHEMA: &str = "CREATE TABLE cmbr_coordination (
    community_id TEXT NOT NULL,
    slot INTEGER NOT NULL CHECK (slot = 1),
    payload TEXT NOT NULL,
    PRIMARY KEY (community_id, slot)
) WITHOUT ROWID;";

/// Current coordination state. Serialization is for trusted storage only.
/// No client may supply this value; it contains no timestamps or event history.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub(crate) generation: u64,
    pub(crate) operation: Option<Operation>,
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpoint")
            .field("busy", &self.is_busy())
            .finish_non_exhaustive()
    }
}

impl Checkpoint {
    /// A pending operation must never be cleared on a timer.
    pub fn is_busy(&self) -> bool {
        self.operation.is_some()
    }

    pub(crate) fn next(&self, operation: Option<Operation>) -> Result<Self> {
        let generation = self
            .generation
            .checked_add(1)
            .filter(|g| *g <= i64::MAX as u64)
            .ok_or(Error::Unavailable)?;
        Ok(Self {
            generation,
            operation,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Operation {
    // Single-leaf writes can be reconciled from their current state.
    Busy,
    Reservation {
        before: cnrl::Record,
        display: String,
        skeleton: String,
    },
    Admission {
        before: cnrl::Record,
    },
}

/// Small durable mutual exclusion boundary, fixed to one community.
/// CAS is strict (including exact retry); only one caller acquires ownership.
/// Lost responses leave the slot busy. Implementations must be atomic and must
/// not expire locks. Sharing the same backend is mandatory across instances.
pub trait Storage: Send + Sync {
    /// Immutable community scope selected by the service.
    fn community(&self) -> &str;
    /// Missing storage returns the default idle checkpoint.
    fn load(&self) -> impl Future<Output = Result<Checkpoint>> + Send;
    /// Replace exactly the expected checkpoint, or return Busy.
    fn compare_exchange(
        &self,
        expected: &Checkpoint,
        next: &Checkpoint,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Real in-memory coordination for tests; clones share the same slot.
#[derive(Clone)]
pub struct MemoryStorage {
    community: String,
    state: Arc<Mutex<Checkpoint>>,
}
impl MemoryStorage {
    /// Create one isolated community coordinator.
    pub fn new(community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        crate::text(&community)?;
        Ok(Self {
            community,
            state: Arc::default(),
        })
    }
}
impl Storage for MemoryStorage {
    fn community(&self) -> &str {
        &self.community
    }
    async fn load(&self) -> Result<Checkpoint> {
        Ok(self.state.lock().await.clone())
    }
    async fn compare_exchange(&self, expected: &Checkpoint, next: &Checkpoint) -> Result<()> {
        validate(expected, next)?;
        let mut current = self.state.lock().await;
        if *current != *expected {
            return Err(Error::Busy);
        }
        *current = next.clone();
        Ok(())
    }
}

/// Persistent coordinator using crlt's scoped immediate transactions.
#[derive(Clone)]
pub struct LibsqlStorage {
    community: String,
    scope: Community,
}
impl LibsqlStorage {
    /// The service owns database creation and migrations, one DB per community.
    pub fn new(db: &crlt::Db, community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        crate::text(&community)?;
        Ok(Self {
            scope: db.community(community.clone())?,
            community,
        })
    }
}
const LOAD: &str = "SELECT payload FROM cmbr_coordination WHERE slot = 1";
const INSERT: &str = "INSERT INTO cmbr_coordination (slot, payload) VALUES (1, ?1)";
const UPDATE: &str = "UPDATE cmbr_coordination SET payload = ?1 WHERE slot = 1";
fn decode(rows: &[crlt::Row]) -> Result<Checkpoint> {
    match rows.first() {
        None => Ok(Checkpoint::default()),
        Some(row) => {
            let checkpoint: Checkpoint =
                serde_json::from_str(row.get_str(0)?).map_err(|_| Error::Unavailable)?;
            if checkpoint.generation == 0 || checkpoint.generation > i64::MAX as u64 {
                return Err(Error::Unavailable);
            }
            Ok(checkpoint)
        }
    }
}
fn validate(previous: &Checkpoint, next: &Checkpoint) -> Result<()> {
    if previous.generation.checked_add(1) != Some(next.generation)
        || next.generation > i64::MAX as u64
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
impl Storage for LibsqlStorage {
    fn community(&self) -> &str {
        &self.community
    }
    async fn load(&self) -> Result<Checkpoint> {
        decode(&self.scope.query(LOAD, ()).await?)
    }
    async fn compare_exchange(&self, expected: &Checkpoint, next: &Checkpoint) -> Result<()> {
        validate(expected, next)?;
        let mut tx = self.scope.tx().await?;
        let rows = tx.query(LOAD, ()).await?;
        if decode(&rows)? != *expected {
            return Err(Error::Busy);
        }
        let payload = serde_json::to_string(next).map_err(|_| Error::Unavailable)?;
        tx.execute(
            if rows.is_empty() { INSERT } else { UPDATE },
            params![payload],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
