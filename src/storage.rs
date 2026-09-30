use crate::{Error, Result};
use crlt::{Community, params};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Append through the service's migration history. No durable lock is stored.
pub const SCHEMA: &str = "CREATE TABLE cmbr_probation (
    community_id TEXT NOT NULL, subject TEXT NOT NULL,
    probation_until INTEGER CHECK (probation_until >= 0 AND probation_until % 86400 = 0),
    PRIMARY KEY (community_id, subject)
) WITHOUT ROWID;
CREATE INDEX cmbr_probation_expiry ON cmbr_probation (community_id, probation_until, subject);
CREATE TABLE cmbr_revocations (
    community_id TEXT NOT NULL, subject TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    pending INTEGER NOT NULL DEFAULT 1 CHECK (pending IN (0,1)),
    PRIMARY KEY (community_id, subject)
) WITHOUT ROWID;
CREATE INDEX cmbr_revocation_pending ON cmbr_revocations (community_id, pending, subject);";

/// Durable request to advance cplc's epoch before further credential issuance.
/// Epoch advancement invalidates all credentials that could contain a removed key.
#[derive(Clone, PartialEq, Eq)]
pub struct Revocation {
    /// Community pseudonym whose authentication or eligibility changed.
    pub member: String,
    /// Compare-and-delete token; a newer revocation cannot be acknowledged away.
    pub generation: u64,
}
impl std::fmt::Debug for Revocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revocation").finish_non_exhaustive()
    }
}

/// Coarse membership facts and a durable revocation outbox, never mutual exclusion.
pub trait Storage: Send + Sync {
    /// Service-selected community capability.
    fn community(&self) -> &str;
    /// None means never initialized; Some(None) means probation has ended.
    fn probation(&self, member: &str) -> impl Future<Output = Result<Option<Option<u64>>>> + Send;
    /// Initialize once after admission. Existing probation never restarts or slides.
    fn initialize_probation(
        &self,
        member: &str,
        until: u64,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delete a passed probation end while retaining the initialized member row.
    fn clear_passed_probation(
        &self,
        member: &str,
        now: u64,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delete a bounded batch of passed probation deadlines through an expiry index.
    fn prune_probation(&self, now: u64, limit: usize) -> impl Future<Output = Result<()>> + Send;
    /// Whether this member still requires a cplc revocation update.
    fn revocation_pending(&self, member: &str) -> impl Future<Output = Result<bool>> + Send;
    /// Mark a security change before its leaf mutation. Conservative invalidation
    /// after a refused mutation is safe; losing a committed revocation is not.
    fn signal_revocation(&self, member: &str) -> impl Future<Output = Result<()>> + Send;
    /// Bounded pending outbox, in deterministic pseudonym order.
    fn revocations(&self, limit: usize) -> impl Future<Output = Result<Vec<Revocation>>> + Send;
    /// Clear only after cplc durably advanced its epoch and published fresh trust.
    fn acknowledge(&self, event: &Revocation) -> impl Future<Output = Result<()>> + Send;
}
fn deadline(until: u64) -> Result<()> {
    if until > i64::MAX as u64 || !until.is_multiple_of(86400) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn limit(value: usize) -> Result<i64> {
    if (1..=1000).contains(&value) {
        Ok(value as i64)
    } else {
        Err(Error::InvalidInput)
    }
}
#[derive(Default)]
struct MemoryState {
    probation: BTreeMap<String, Option<u64>>,
    revocations: BTreeMap<String, (u64, bool)>,
}
/// Real in-memory storage. Clones share state; no timestamps of activity exist.
#[derive(Clone)]
pub struct MemoryStorage {
    community: String,
    state: Arc<Mutex<MemoryState>>,
}
impl MemoryStorage {
    /// Create an isolated community store.
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
    async fn probation(&self, member: &str) -> Result<Option<Option<u64>>> {
        crate::text(member)?;
        Ok(self.state.lock().await.probation.get(member).copied())
    }
    async fn initialize_probation(&self, member: &str, until: u64) -> Result<()> {
        crate::text(member)?;
        deadline(until)?;
        self.state
            .lock()
            .await
            .probation
            .entry(member.into())
            .or_insert(Some(until));
        Ok(())
    }
    async fn clear_passed_probation(&self, member: &str, now: u64) -> Result<()> {
        crate::text(member)?;
        if let Some(end) = self.state.lock().await.probation.get_mut(member)
            && end.is_some_and(|end| end <= now)
        {
            *end = None;
        }
        Ok(())
    }
    async fn prune_probation(&self, now: u64, count: usize) -> Result<()> {
        limit(count)?;
        let mut state = self.state.lock().await;
        for end in state
            .probation
            .values_mut()
            .filter(|end| end.is_some_and(|until| until <= now))
            .take(count)
        {
            *end = None;
        }
        Ok(())
    }
    async fn revocation_pending(&self, member: &str) -> Result<bool> {
        crate::text(member)?;
        Ok(self
            .state
            .lock()
            .await
            .revocations
            .get(member)
            .is_some_and(|(_, pending)| *pending))
    }
    async fn signal_revocation(&self, member: &str) -> Result<()> {
        crate::text(member)?;
        let mut state = self.state.lock().await;
        let value = state.revocations.entry(member.into()).or_default();
        value.0 = value
            .0
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Unavailable)?;
        value.1 = true;
        Ok(())
    }
    async fn revocations(&self, count: usize) -> Result<Vec<Revocation>> {
        limit(count)?;
        Ok(self
            .state
            .lock()
            .await
            .revocations
            .iter()
            .filter(|(_, (_, pending))| *pending)
            .take(count)
            .map(|(member, generation)| Revocation {
                member: member.clone(),
                generation: generation.0,
            })
            .collect())
    }
    async fn acknowledge(&self, event: &Revocation) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(value) = state.revocations.get_mut(&event.member)
            && value.0 == event.generation
        {
            value.1 = false;
        }
        Ok(())
    }
}
/// Persistent membership facts using the one service-owned crlt pool.
#[derive(Clone)]
pub struct LibsqlStorage {
    community: String,
    scope: Community,
}
impl LibsqlStorage {
    /// Bind an already migrated community database.
    pub fn new(db: &crlt::Db, community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        crate::text(&community)?;
        Ok(Self {
            scope: db.community(community.clone())?,
            community,
        })
    }
}
const PROBATION: &str = "SELECT probation_until FROM cmbr_probation WHERE subject = ?1";
fn probation(rows: &[crlt::Row]) -> Result<Option<Option<u64>>> {
    rows.first()
        .map(|row| match row.get_value(0)? {
            crlt::Value::Null => Ok(None),
            crlt::Value::Integer(value) if *value >= 0 && value % 86400 == 0 => {
                Ok(Some(*value as u64))
            }
            _ => Err(Error::Unavailable),
        })
        .transpose()
}
impl Storage for LibsqlStorage {
    fn community(&self) -> &str {
        &self.community
    }
    async fn probation(&self, member: &str) -> Result<Option<Option<u64>>> {
        crate::text(member)?;
        probation(&self.scope.query(PROBATION, [member]).await?)
    }
    async fn initialize_probation(&self, member: &str, until: u64) -> Result<()> {
        crate::text(member)?;
        deadline(until)?;
        let mut tx = self.scope.tx().await?;
        if tx.query(PROBATION, [member]).await?.is_empty() {
            tx.execute(
                "INSERT INTO cmbr_probation (subject, probation_until) VALUES (?1, ?2)",
                params![member, until as i64],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn clear_passed_probation(&self, member: &str, now: u64) -> Result<()> {
        crate::text(member)?;
        let now = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
        self.scope.execute("UPDATE cmbr_probation SET probation_until = NULL WHERE subject = ?1 AND probation_until <= ?2", params![member, now]).await?;
        Ok(())
    }
    async fn prune_probation(&self, now: u64, count: usize) -> Result<()> {
        let at = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
        let rows = self.scope.query("SELECT subject FROM cmbr_probation WHERE probation_until <= ?1 ORDER BY probation_until, subject LIMIT ?2", params![at, limit(count)?]).await?;
        for row in rows {
            self.clear_passed_probation(row.get_str(0)?, now).await?;
        }
        Ok(())
    }
    async fn revocation_pending(&self, member: &str) -> Result<bool> {
        crate::text(member)?;
        Ok(self
            .scope
            .query(
                "SELECT pending FROM cmbr_revocations WHERE subject = ?1",
                [member],
            )
            .await?
            .first()
            .map(|row| row.get_i64(0))
            .transpose()?
            .is_some_and(|pending| pending == 1))
    }
    async fn signal_revocation(&self, member: &str) -> Result<()> {
        crate::text(member)?;
        let mut tx = self.scope.tx().await?;
        let rows = tx
            .query(
                "SELECT generation FROM cmbr_revocations WHERE subject = ?1",
                [member],
            )
            .await?;
        if let Some(row) = rows.first() {
            let next = row.get_i64(0)?.checked_add(1).ok_or(Error::Unavailable)?;
            tx.execute(
                "UPDATE cmbr_revocations SET generation = ?1, pending = 1 WHERE subject = ?2",
                params![next, member],
            )
            .await?;
        } else {
            tx.execute(
                "INSERT INTO cmbr_revocations (subject, generation) VALUES (?1, 1)",
                [member],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn revocations(&self, count: usize) -> Result<Vec<Revocation>> {
        self.scope
            .query(
                "SELECT subject, generation FROM cmbr_revocations WHERE pending = 1 ORDER BY subject LIMIT ?1",
                [limit(count)?],
            )
            .await?
            .iter()
            .map(|row| {
                let generation = row.get_i64(1)?;
                if generation <= 0 {
                    return Err(Error::Unavailable);
                }
                Ok(Revocation {
                    member: row.get_str(0)?.into(),
                    generation: generation as u64,
                })
            })
            .collect()
    }
    async fn acknowledge(&self, event: &Revocation) -> Result<()> {
        crate::text(&event.member)?;
        let generation = i64::try_from(event.generation).map_err(|_| Error::InvalidInput)?;
        self.scope
            .execute(
                "UPDATE cmbr_revocations SET pending = 0 WHERE subject = ?1 AND generation = ?2",
                params![event.member.as_str(), generation],
            )
            .await?;
        Ok(())
    }
}

// A process-local per-member queue; no guard survives cancellation/error/process
// exit and no database Busy marker exists. Service writers share this registry.
// Leaf row revisions and unique constraints still fence stale/competing writes.
type MemberLocks = BTreeMap<(String, cpky::Uuid), Weak<Mutex<()>>>;
pub(crate) async fn member_lock(community: &str, user: cpky::Uuid) -> OwnedMutexGuard<()> {
    static LOCKS: OnceLock<StdMutex<MemberLocks>> = OnceLock::new();
    let lock = {
        let mut locks = LOCKS
            .get_or_init(StdMutex::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, weak| weak.strong_count() > 0);
        let weak = locks.entry((community.into(), user)).or_default();
        match weak.upgrade() {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(Mutex::new(()));
                *weak = Arc::downgrade(&lock);
                lock
            }
        }
    };
    lock.lock_owned().await
}

#[cfg(test)]
mod tests;
