use std::sync::Arc;

use chrono::{DateTime, Datelike, Utc};
use cpky::{Authentication, Uuid};
use cpns::server::{ChangeTokenVerifier, Pin, Pins};

use crate::{Checkpoint, Error, Result, Storage, storage::Operation};
use cnrl::{Event, Record, State, Storage as _};
use crgs::{Storage as _, Transaction as _};

/// Resolved service configuration. No product policy defaults are supplied.
pub struct Config {
    /// Pending registration duration, in whole UTC days.
    pub pending_days: u32,
    /// The action whose policy and legal scope govern membership.
    pub membership_action: String,
    /// Existing handle retention is materialized by crgs.
    pub release_period: crgs::ReleasePeriod,
    /// Community-specific WebAuthn relying party ID.
    pub rp_id: String,
    /// Explicit allowed HTTPS origins, validated by cpky.
    pub origins: Vec<cpky::Url>,
}

/// Server-only single-use registration state, bound to its cpky instance.
pub struct PendingRegistration {
    user: Uuid,
    pending: cpky::PendingRegistration,
}
/// Server-only single-use login state.
pub struct PendingLogin {
    user: Uuid,
    pending: cpky::PendingAuthentication,
}

/// A successful passkey login always returns to the enrolment lobby.
/// Neither this result nor an admitted row is an access credential.
pub struct Login {
    /// Opaque in-process authentication. The service owns session lifetime.
    pub authentication: Authentication,
    /// Current enrolment, possibly pending or lapsed.
    pub enrolment: Record,
}

struct SharedClock<C>(Arc<C>);
impl<C: clbs::Clock> clbs::Clock for SharedClock<C> {
    fn now(&self) -> clbs::Result<i64> {
        self.0.now()
    }
}

/// Membership service for one community. All leaf capabilities stay private.
/// The coordinator must be shared by every writer to this community database.
/// Supply real, fail-closed change-spend and self-ban verification adapters.
pub struct Membership<S, V, L, C = clbs::SystemClock> {
    storage: S,
    passkeys: Arc<cpky::Passkeys<cpky::LibsqlStore>>,
    enrol: cnrl::Enrol<cnrl::LibsqlStorage>,
    enrol_store: cnrl::LibsqlStorage,
    register: crgs::Register<crgs::LibsqlStorage>,
    register_store: crgs::LibsqlStorage,
    pins: Pins<cpns::server::libsql::LibsqlStore, V>,
    legal: clbs::Gate<clbs::LibsqlStore, L, SharedClock<C>>,
    clock: Arc<C>,
    action: String,
}

impl<S: Storage, V: ChangeTokenVerifier, L: clbs::Verifier, C: clbs::Clock> Membership<S, V, L, C> {
    /// Construct from a migrated service-owned database and a multithreaded
    /// Tokio runtime. All leaves use the coordinator's immutable community.
    /// The service authenticates global pseudonyms before registration, supplies
    /// fresh verified policy/gate inputs, and authorizes restricted pin fields.
    pub fn new(
        db: &crlt::Db,
        storage: S,
        config: Config,
        tokens: V,
        legal: L,
        clock: C,
    ) -> Result<Self> {
        crate::text(storage.community())?;
        crate::text(&config.membership_action)?;
        let community = storage.community();
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| Error::InvalidInput)?;
        let passkeys = cpky::Passkeys::new(
            cpky::LibsqlStore::new(db, community, runtime)?,
            community,
            &config.rp_id,
            &config.origins,
        )?;
        let enrol_store = cnrl::LibsqlStorage::new(db, community)?;
        let enrol = cnrl::Enrol::new(
            enrol_store.clone(),
            cnrl::Config::new(config.pending_days, &config.membership_action)?,
        );
        let register_store = crgs::LibsqlStorage::new(db.community(community)?);
        let register = crgs::Register::new(register_store.clone(), config.release_period);
        let pins = Pins::new(
            cpns::server::libsql::LibsqlStore::new(db, community)?,
            tokens,
        );
        let clock = Arc::new(clock);
        let legal = clbs::Gate::new(
            clbs::LibsqlStore::new(db, community)?,
            legal,
            SharedClock(clock.clone()),
        );
        Ok(Self {
            storage,
            passkeys: Arc::new(passkeys),
            enrol,
            enrol_store,
            register,
            register_store,
            pins,
            legal,
            clock,
            action: config.membership_action,
        })
    }

    /// Begin first registration for a service-verified community pseudonym.
    /// UUIDs are community-local, nonnil and must not be derived from global IDs.
    /// This trusted API is not permission to bind arbitrary client-supplied IDs.
    /// Adding more passkeys needs a separate approved device flow, not this API.
    pub async fn begin_registration(
        &self,
        user: Uuid,
        pseudonym: &str,
    ) -> Result<(cpky::CreationChallengeResponse, PendingRegistration)> {
        crate::text(pseudonym)?;
        if user.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.run(async |_| {
            self.unrestricted(pseudonym).await?;
            let row = self.enrol.start(user, pseudonym, self.now()?).await?;
            if row.state() != State::Started || !self.credentials(user).await?.is_empty() {
                return Err(Error::Transition);
            }
            let keys = self.passkeys.clone();
            let (challenge, pending) = blocking(move || keys.start_registration(user)).await?;
            Ok((challenge, PendingRegistration { user, pending }))
        })
        .await
    }

    /// Verify and persist the passkey, then apply the actual cpky receipt to cnrl.
    /// A lost response is reconciled by state/resume from cpky's committed row.
    pub async fn finish_registration(
        &self,
        state: PendingRegistration,
        response: cpky::RegisterPublicKeyCredential,
    ) -> Result<Record> {
        self.run(async |_| {
            let now = self.now()?;
            let row = self.live(state.user, now).await?;
            if row.state() != State::Started || !self.credentials(state.user).await?.is_empty() {
                return Err(Error::Transition);
            }
            let date = date(now)?;
            let month = cpky::CreationMonth::new(date.year() as u16, date.month() as u8)?;
            let keys = self.passkeys.clone();
            let receipt =
                blocking(move || keys.finish_registration(state.pending, &response, month)).await?;
            if receipt.member() != state.user {
                return Err(Error::Identity);
            }
            Ok(self
                .enrol
                .apply(&row, Event::PasskeyRegistered(&receipt), now)
                .await?)
        })
        .await
    }

    /// Account-first login; discoverable login remains a cpky integration issue.
    pub async fn begin_login(
        &self,
        user: Uuid,
    ) -> Result<(cpky::RequestChallengeResponse, PendingLogin)> {
        self.run(async |_| {
            self.live(user, self.now()?).await?;
            let keys = self.passkeys.clone();
            let (challenge, pending) = blocking(move || keys.start_authentication(user)).await?;
            Ok((challenge, PendingLogin { user, pending }))
        })
        .await
    }

    /// Commit cpky's counter checks and return authenticated enrolment to the lobby.
    /// This does not extend a lease or record a login date.
    pub async fn finish_login(
        &self,
        state: PendingLogin,
        response: cpky::PublicKeyCredential,
    ) -> Result<Login> {
        self.run(async |_| {
            let keys = self.passkeys.clone();
            let authentication =
                blocking(move || keys.finish_authentication(state.pending, &response)).await?;
            if authentication.member() != state.user {
                return Err(Error::Identity);
            }
            let enrolment = self.authenticated(&authentication, self.now()?).await?;
            Ok(Login {
                authentication,
                enrolment,
            })
        })
        .await
    }

    /// Trusted service lookup, including expiry, lost registration receipts and
    /// current legal restrictions. Use `resume` for a member-facing endpoint.
    pub async fn enrolment_state(&self, user: Uuid) -> Result<Record> {
        self.run(async |_| self.sync(user, self.now()?).await).await
    }

    /// Resume the stable pseudonym binding after a committed cpky authentication.
    pub async fn resume(&self, auth: &Authentication) -> Result<Record> {
        self.run(async |_| self.authenticated(auth, self.now()?).await)
            .await
    }

    /// Validate a candidate and check the actual register's reservation/lease state.
    /// Callers must throttle this unauthenticated lookup and supply current reserved names.
    pub async fn is_handle_available(&self, handle: &str, reserved: &[String]) -> Result<bool> {
        let checked = cgrd::check_handle(handle, reserved).map_err(|_| Error::InvalidInput)?;
        self.run(async |_| {
            Ok(self
                .register
                .is_handle_available(&checked.skeleton, date(self.now()?)?)
                .await?)
        })
        .await
    }

    /// Revalidate a session's exact credential, including immediate revocation.
    /// An opaque cpky authentication alone is not a renewable bearer capability.
    pub async fn session_is_active(
        &self,
        auth: &Authentication,
        credential: &cpky::CredentialID,
    ) -> Result<bool> {
        self.run(async |_| {
            self.authenticated(auth, self.now()?).await?;
            Ok(self
                .credentials(auth.member())
                .await?
                .iter()
                .any(|key| key.credential_id() == credential && !key.is_revoked()))
        })
        .await
    }

    /// Normalize and validate with cgrd, then reserve its skeleton through crgs.
    /// The reserved-name list must come from authenticated, current policy.
    pub async fn reserve_handle(
        &self,
        auth: &Authentication,
        handle: &str,
        reserved: &[String],
    ) -> Result<Record> {
        let checked = cgrd::check_handle(handle, reserved).map_err(|_| Error::InvalidInput)?;
        self.run(async |checkpoint| {
            let now = self.now()?;
            let row = self.authenticated(auth, now).await?;
            if !matches!(
                row.state(),
                State::PasskeyRegistered | State::HandleReserved | State::GatesInProgress
            ) {
                return Err(Error::Transition);
            }
            let reservation = crgs::Reservation {
                member_id: row.member_id(),
                handle: crgs::Handle::new(&checked.normalized, &checked.skeleton)?,
                expires_at: date(row.expires_at().ok_or(Error::Transition)?)?,
            };
            self.prepare(
                checkpoint,
                Operation::Reservation {
                    user: row.user(),
                    display: checked.normalized,
                    skeleton: checked.skeleton,
                },
            )
            .await?;
            let receipt = match self.register.reserve_handle(reservation, date(now)?).await {
                Ok(r) => r,
                Err(e) => return self.register_error(checkpoint, e).await,
            };
            Ok(self
                .enrol
                .apply(&row, Event::HandleReserved(&receipt), now)
                .await?)
        })
        .await
    }

    /// Evaluate the real rulebook and return transient missing requirements.
    /// Snapshot authenticity/freshness and gate verification belong to cmnt/cgts.
    pub async fn lobby(
        &self,
        auth: &Authentication,
        policy: &crbk::Snapshot,
        gates: &[crbk::GateResult],
    ) -> Result<(Record, crbk::Decision)> {
        self.run(async |_| {
            let now = self.now()?;
            let row = self.authenticated(auth, now).await?;
            Ok(self.enrol.evaluate(&row, policy, gates, now).await?)
        })
        .await
    }

    /// Admit or renew only after a fresh positive rulebook decision and clbs check.
    /// Roles start as Member; role administration belongs to the owning service.
    /// Uses the stored reservation/handle; callers cannot substitute a skeleton.
    pub async fn admit(
        &self,
        auth: &Authentication,
        policy: &crbk::Snapshot,
        gates: &[crbk::GateResult],
        lease: crgs::YearMonth,
    ) -> Result<Record> {
        self.run(async |checkpoint| {
            let now = self.now()?;
            let row = self.authenticated(auth, now).await?;
            let (row, decision) = self.enrol.evaluate(&row, policy, gates, now).await?;
            if !decision.allowed {
                return Err(Error::Policy);
            }
            let current_month =
                crgs::YearMonth::new(date(now)?.year() as u16, date(now)?.month() as u8)?;
            if lease < current_month {
                return Err(Error::InvalidInput);
            }
            let handle = self.current_handle(&row).await?.ok_or(Error::Transition)?;
            self.prepare(
                checkpoint,
                Operation::Admission {
                    user: row.user(),
                    lease_year: lease.year(),
                    lease_month: lease.month(),
                },
            )
            .await?;
            let member = if matches!(row.state(), State::Admitted | State::Lapsed) {
                match self
                    .register
                    .extend_lease(&row.member_id(), lease, date(now)?)
                    .await
                {
                    Ok(member) => member,
                    Err(e) => return self.register_error(checkpoint, e).await,
                }
            } else {
                match self
                    .register
                    .admit(
                        crgs::Admission {
                            id: row.member_id(),
                            handle,
                            role: crgs::Role::Member,
                            lease_end: lease,
                        },
                        date(now)?,
                    )
                    .await
                {
                    Ok(member) => member,
                    Err(e) => return self.register_error(checkpoint, e).await,
                }
            };
            if member.handle.is_none() {
                self.enrol
                    .apply(&row, Event::RegisterReleased(&member), now)
                    .await?;
                self.prepare(checkpoint, Operation::Busy).await?;
                return Err(Error::Transition);
            }
            Ok(self
                .enrol
                .apply(
                    &row,
                    Event::AdmissionRecorded {
                        member: &member,
                        decision: &decision,
                    },
                    now,
                )
                .await?)
        })
        .await
    }

    /// Lapse admission using the rulebook's current negative decision.
    /// A positive verdict never becomes an arbitrary administrative lapse.
    pub async fn lapse(
        &self,
        auth: &Authentication,
        policy: &crbk::Snapshot,
        gates: &[crbk::GateResult],
    ) -> Result<Record> {
        let (row, decision) = self.lobby(auth, policy, gates).await?;
        if decision.allowed {
            return Err(Error::Policy);
        }
        Ok(row)
    }

    /// Insert a device-created digest. The caller authorizes the schema field;
    /// values and salts never enter this API or permanent storage.
    pub async fn pin(
        &self,
        auth: &Authentication,
        field: &str,
        fingerprint: cpns::Fingerprint,
    ) -> Result<Pin> {
        self.run(async |_| {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self.pins.pin(row.subject(), field, fingerprint).await?)
        })
        .await
    }

    /// Change only through cpns's exact, already-spent authorization contract.
    /// After an uncertain result, read the pin and reconcile before retrying.
    pub async fn change_pin(
        &self,
        auth: &Authentication,
        field: &str,
        expected: Pin,
        replacement: cpns::Fingerprint,
        token: &V::Token,
    ) -> Result<Pin> {
        self.run(async |_| {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self
                .pins
                .change(row.subject(), field, expected, replacement, token)
                .await?)
        })
        .await
    }

    /// Read the current fingerprint and revision, without access history.
    pub async fn get_pin(&self, auth: &Authentication, field: &str) -> Result<Option<Pin>> {
        self.run(async |_| {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self.pins.get(row.subject(), field).await?)
        })
        .await
    }

    /// Read the current register record for credential issuance or the lobby.
    /// The outer service must validate the coarse lease before granting access.
    pub async fn member(&self, auth: &Authentication) -> Result<Option<crgs::Member>> {
        self.run(async |_| {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self.register.member(&row.member_id()).await?)
        })
        .await
    }

    /// Return the canonical reserved or admitted handle for the lobby.
    pub async fn handle(&self, auth: &Authentication) -> Result<Option<crgs::Handle>> {
        self.run(async |_| {
            let row = self.authenticated(auth, self.now()?).await?;
            self.current_handle(&row).await
        })
        .await
    }

    /// Revoke one owned credential. Losing the last live credential releases the
    /// lifecycle immediately; crgs retains its existing coarse handle deadline.
    pub async fn revoke_passkey(
        &self,
        auth: &Authentication,
        credential: cpky::CredentialID,
    ) -> Result<Record> {
        self.run(async |_| {
            let row = self.authenticated(auth, self.now()?).await?;
            let keys = self.passkeys.clone();
            let user = row.user();
            blocking(move || keys.revoke(user, &credential)).await?;
            self.release_if_lost(row, self.now()?).await
        })
        .await
    }

    /// Trusted lost-key maintenance. Refuses while any credential remains live.
    /// Physical loss cannot be inferred: the service must first revoke the keys
    /// through an authorized device protocol. There is no recovery override.
    pub async fn release(&self, user: Uuid) -> Result<Record> {
        self.run(async |_| {
            let now = self.now()?;
            let row = self.sync(user, now).await?;
            if row.state().is_terminal() {
                return Ok(row);
            }
            if self
                .credentials(user)
                .await?
                .iter()
                .any(|k| !k.is_revoked())
            {
                return Err(Error::Transition);
            }
            self.release_if_lost(row, now).await
        })
        .await
    }

    /// Confirm permanent voluntary termination through clbs's fresh, intent-bound
    /// verifier. A normal login result alone is insufficient self-ban evidence.
    /// Identical signed retries remain verifiable even after lifecycle release.
    pub async fn self_ban(
        &self,
        auth: &Authentication,
        order: &clbs::SignedOrder,
    ) -> Result<Record> {
        self.run(async |_| {
            self.identity(auth)?;
            let row = self
                .enrol_store
                .load(auth.member())
                .await?
                .ok_or(Error::Transition)?;
            if order.order.community != self.storage.community()
                || order.order.subject != row.subject()
            {
                return Err(Error::Identity);
            }
            self.legal.self_ban(order).await?;
            self.sync(row.user(), self.now()?).await
        })
        .await
    }

    /// Bounded pending expiry, claim cleanup and crgs retention release, serialized
    /// with every registration/admission. Call periodically even without logins.
    pub async fn maintain(&self, limit: usize) -> Result<()> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::InvalidInput);
        }
        self.run(async |_| {
            let now = self.now()?;
            self.enrol.expire_due(now, limit).await?;
            self.enrol.cleanup(&self.register, limit).await?;
            self.register.release_expired(date(now)?, limit).await?;
            Ok(())
        })
        .await
    }

    /// Recover a crash ONLY after all service writers and blocking workers using
    /// this community have stopped. Run once under an external startup/recovery
    /// leader; concurrent recovery or recovery of a live worker is unsupported.
    /// No lock is stolen on a timeout. Errors leave the marker intact.
    /// A recovered receipt is historical completion, never an access grant: cmnt
    /// must obtain a current lobby verdict before issuing a credential.
    pub async fn recover_after_quiescence(&self) -> Result<()> {
        let checkpoint = self.storage.load().await?;
        let Some(operation) = &checkpoint.operation else {
            return Ok(());
        };
        let now = self.now()?;
        match operation {
            Operation::Busy => {}
            Operation::Reservation {
                user,
                display,
                skeleton,
            } => {
                let before = self
                    .enrol_store
                    .load(*user)
                    .await?
                    .ok_or(Error::Unavailable)?;
                self.check_record(&before)?;
                let deadline = before.expires_at();
                if before.state().is_terminal() || deadline.is_some_and(|end| now >= end) {
                    self.register
                        .cancel_reservation(&before.member_id(), skeleton)
                        .await?;
                    self.enrol.get(before.user(), now).await?;
                } else {
                    let deadline = deadline.ok_or(Error::Unavailable)?;
                    let result = self
                        .register
                        .reserve_handle(
                            crgs::Reservation {
                                member_id: before.member_id(),
                                handle: crgs::Handle::new(display, skeleton)?,
                                expires_at: date(deadline)?,
                            },
                            date(now)?,
                        )
                        .await;
                    match result {
                        Ok(receipt) => {
                            self.enrol
                                .apply(&before, Event::HandleReserved(&receipt), now)
                                .await?;
                        }
                        Err(crgs::Error::Storage) => return Err(Error::Unavailable),
                        // A crash may follow a known register refusal before its
                        // marker was cleared. No receipt exists in that case.
                        Err(_) => {}
                    }
                }
            }
            Operation::Admission {
                user,
                lease_year,
                lease_month,
            } => {
                let before = self
                    .enrol_store
                    .load(*user)
                    .await?
                    .ok_or(Error::Unavailable)?;
                self.check_record(&before)?;
                if !before.state().is_terminal()
                    && let Some(member) = self.register.member(&before.member_id()).await?
                    && member.lease_end >= crgs::YearMonth::new(*lease_year, *lease_month)?
                {
                    // This marker is written only after a verified positive policy
                    // decision. Finish its receipt before cnrl can expire it.
                    let logical = before.expires_at().map_or(now, |end| now.min(end - 1));
                    let lease_start = chrono::NaiveDate::from_ymd_opt(
                        member.lease_end.year().into(),
                        member.lease_end.month().into(),
                        1,
                    )
                    .ok_or(Error::Unavailable)?
                    .and_hms_opt(0, 0, 0)
                    .ok_or(Error::Unavailable)?
                    .and_utc()
                    .timestamp();
                    let logical = logical.min(lease_start);
                    let decision = crbk::Decision {
                        allowed: true,
                        missing: Vec::new(),
                    };
                    self.enrol
                        .apply(
                            &before,
                            if member.handle.is_none() {
                                Event::RegisterReleased(&member)
                            } else {
                                Event::AdmissionRecorded {
                                    member: &member,
                                    decision: &decision,
                                }
                            },
                            logical,
                        )
                        .await?;
                }
            }
        }
        self.storage
            .compare_exchange(&checkpoint, &checkpoint.next(None)?)
            .await
    }

    fn now(&self) -> Result<i64> {
        let now = self.clock.now()?;
        date(now)?;
        Ok(now)
    }
    fn identity(&self, auth: &Authentication) -> Result<()> {
        if auth.community() != self.storage.community() {
            Err(Error::Identity)
        } else {
            Ok(())
        }
    }
    fn check_record(&self, row: &Record) -> Result<()> {
        if row.community() != self.storage.community() {
            Err(Error::Identity)
        } else {
            Ok(())
        }
    }
    async fn credentials(&self, user: Uuid) -> Result<Vec<cpky::StoredPasskey>> {
        let keys = self.passkeys.clone();
        blocking(move || keys.list(user)).await
    }
    async fn current_handle(&self, row: &Record) -> Result<Option<crgs::Handle>> {
        if matches!(row.state(), State::Admitted | State::Lapsed) {
            return Ok(self
                .register
                .member(&row.member_id())
                .await?
                .and_then(|member| member.handle));
        }
        let mut tx = self.register_store.begin().await?;
        let reservation = tx.reservation(&row.member_id()).await?;
        tx.commit().await?;
        Ok(reservation.map(|reservation| reservation.handle))
    }
    async fn unrestricted(&self, subject: &str) -> Result<()> {
        match self.legal.check_action(subject, &self.action).await? {
            clbs::State::Green => Ok(()),
            clbs::State::Red(_) => Err(Error::Restricted),
        }
    }
    async fn authenticated(&self, auth: &Authentication, now: i64) -> Result<Record> {
        self.identity(auth)?;
        self.live(auth.member(), now).await
    }
    async fn live(&self, user: Uuid, now: i64) -> Result<Record> {
        let row = self.sync(user, now).await?;
        self.unrestricted(row.subject()).await?;
        if row.state().is_terminal() {
            return Err(Error::Transition);
        }
        Ok(row)
    }
    async fn sync(&self, user: Uuid, now: i64) -> Result<Record> {
        let mut row = self.enrol.get(user, now).await?;
        if row.state().is_terminal() {
            return Ok(row);
        }
        let credentials = self.credentials(user).await?;
        if row.state() == State::Started {
            if let Some(key) = credentials.iter().find(|key| !key.is_revoked()) {
                row = self
                    .enrol
                    .apply(&row, Event::PasskeyRegistered(key), now)
                    .await?;
            }
        } else if !credentials.iter().any(|key| !key.is_revoked()) {
            return Ok(self.enrol.apply(&row, Event::AllPasskeysLost, now).await?);
        }
        if let clbs::State::Red(restrictions) =
            self.legal.check_action(row.subject(), &self.action).await?
        {
            for restriction in restrictions {
                let record = self
                    .legal
                    .record(&restriction.order_id)
                    .await?
                    .ok_or(Error::Unavailable)?;
                row = self
                    .enrol
                    .apply(&row, Event::Restriction(&record), now)
                    .await?;
                if row.state().is_terminal() {
                    return Ok(row);
                }
            }
        }
        if matches!(row.state(), State::Admitted | State::Lapsed)
            && let Some(member) = self.register.member(&row.member_id()).await?
            && member.handle.is_none()
        {
            row = self
                .enrol
                .apply(&row, Event::RegisterReleased(&member), now)
                .await?;
        }
        Ok(row)
    }
    async fn release_if_lost(&self, row: Record, now: i64) -> Result<Record> {
        if row.state().is_terminal()
            || self
                .credentials(row.user())
                .await?
                .iter()
                .any(|key| !key.is_revoked())
        {
            return Ok(row);
        }
        Ok(self.enrol.apply(&row, Event::AllPasskeysLost, now).await?)
    }
    async fn prepare(&self, current: &mut Checkpoint, operation: Operation) -> Result<()> {
        let next = current.next(Some(operation))?;
        self.storage.compare_exchange(current, &next).await?;
        *current = next;
        Ok(())
    }
    async fn register_error<T>(
        &self,
        checkpoint: &mut Checkpoint,
        error: crgs::Error,
    ) -> Result<T> {
        let error = Error::from(error);
        if error != Error::Unavailable {
            self.prepare(checkpoint, Operation::Busy).await?;
        }
        Err(error)
    }
    async fn run<T>(&self, operation: impl AsyncFnOnce(&mut Checkpoint) -> Result<T>) -> Result<T> {
        let idle = self.storage.load().await?;
        if idle.is_busy() {
            return Err(Error::Busy);
        }
        let mut checkpoint = idle.next(Some(Operation::Busy))?;
        self.storage.compare_exchange(&idle, &checkpoint).await?;
        let result = operation(&mut checkpoint).await;
        if result.is_ok()
            || (result.as_ref().err() != Some(&Error::Unavailable)
                && checkpoint.operation == Some(Operation::Busy))
        {
            self.storage
                .compare_exchange(&checkpoint, &checkpoint.next(None)?)
                .await?;
        }
        result
    }
}

fn date(now: i64) -> Result<DateTime<Utc>> {
    let date = DateTime::from_timestamp(now, 0).ok_or(Error::InvalidInput)?;
    if now < 0 || !(1..=9999).contains(&date.year()) {
        return Err(Error::InvalidInput);
    }
    Ok(date)
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> std::result::Result<T, cpky::Error> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(Into::into)
}

#[cfg(test)]
mod tests;
