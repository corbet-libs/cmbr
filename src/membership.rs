use std::sync::Arc;

use chrono::{DateTime, Datelike, Utc};
use cpky::{Authentication, Uuid};
use cpns::server::{ChangeTokenVerifier, Pin, Pins};

use crate::{Error, Result, Storage};
use cnrl::{Event, Record, State, Storage as _};

/// Resolved service configuration. No product policy defaults are supplied.
pub struct Config {
    /// Pending registration duration, in whole UTC days.
    pub pending_days: u32,
    /// The action whose policy and legal scope govern membership.
    pub membership_action: String,
    /// Existing handle retention is materialized by crgs.
    pub release_period: crgs::ReleasePeriod,
    /// Maximum lease extension from the current month (1–24 months).
    pub lease_months: u32,
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

/// Current lobby response. Warnings are part of the API, not optional UI policy.
pub struct Lobby {
    /// Pure current enrolment view.
    pub enrolment: Record,
    /// cplc's current policy decision.
    pub decision: crbk::Decision,
    /// Required no-return and device-resilience messages.
    pub warnings: Vec<Warning>,
}
/// Product warnings returned before the irreversible no-return boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    /// Finish before this exclusive UTC-day deadline; expiry permanently prevents rejoining.
    RegistrationExpires {
        /// Exclusive UTC-day registration deadline.
        deadline: i64,
    },
    /// Register a second device or use a synced passkey; losing every passkey permanently prevents rejoining.
    AddSecondDeviceOrSyncedPasskey,
}

struct SharedClock<C>(Arc<C>);
impl<C: clbs::Clock> clbs::Clock for SharedClock<C> {
    /// Durable revocation events for cmnt to forward to cplc before issuance.
    pub async fn revocations(&self, limit: usize) -> Result<Vec<crate::Revocation>> {
        self.storage.revocations(limit).await
    }
    /// Acknowledge only after the matching cplc epoch update and publication.
    pub async fn acknowledge_revocation(&self, event: &crate::Revocation) -> Result<()> {
        self.storage.acknowledge(event).await
    }

    fn now(&self) -> clbs::Result<i64> {
        self.0.now()
    }
}

/// Membership service for one community. All leaf capabilities stay private.
/// The coordinator must be shared by every writer to this community database.
/// Supply real, fail-closed change-spend and self-ban verification adapters.
pub struct Membership<S, V, L, C = clbs::SystemClock> {
    storage: Arc<S>,
    passkeys: Arc<cpky::Passkeys<cpky::LibsqlStore>>,
    enrol: Arc<cnrl::Enrol<cnrl::LibsqlStorage>>,
    enrol_store: cnrl::LibsqlStorage,
    register: Arc<crgs::Register<crgs::LibsqlStorage>>,
    register_store: crgs::LibsqlStorage,
    pins: Arc<Pins<cpns::server::libsql::LibsqlStore, V>>,
    legal: Arc<clbs::Gate<clbs::LibsqlStore, L, SharedClock<C>>>,
    clock: Arc<C>,
    action: String,
    lease_months: u32,
}

impl<S, V, L, C> Clone for Membership<S, V, L, C> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            passkeys: self.passkeys.clone(),
            enrol: self.enrol.clone(),
            enrol_store: self.enrol_store.clone(),
            register: self.register.clone(),
            register_store: self.register_store.clone(),
            pins: self.pins.clone(),
            legal: self.legal.clone(),
            clock: self.clock.clone(),
            action: self.action.clone(),
            lease_months: self.lease_months,
        }
    }
}

impl<
    S: Storage + 'static,
    V: ChangeTokenVerifier + 'static,
    L: clbs::Verifier + 'static,
    C: clbs::Clock + 'static,
> Membership<S, V, L, C>
{
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
        if !(1..=24).contains(&config.lease_months) {
            return Err(Error::InvalidInput);
        }
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
            storage: Arc::new(storage),
            passkeys: Arc::new(passkeys),
            enrol: Arc::new(enrol),
            enrol_store,
            register: Arc::new(register),
            register_store,
            pins: Arc::new(pins),
            legal: Arc::new(legal),
            clock,
            action: config.membership_action,
            lease_months: config.lease_months,
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
        async {
            self.unrestricted(pseudonym).await?;
            let row = self.enrol.start(user, pseudonym, self.now()?).await?;
            if row.state() != State::Started || !self.credentials(user).await?.is_empty() {
                return Err(Error::Transition);
            }
            let keys = self.passkeys.clone();
            let (challenge, pending) = blocking(move || keys.start_registration(user)).await?;
            Ok((challenge, PendingRegistration { user, pending }))
        }
        .await
    }

    /// Verify and persist the passkey, then apply the actual cpky receipt to cnrl.
    /// A lost response is reconciled by state/resume from cpky's committed row.
    pub async fn finish_registration(
        &self,
        state: PendingRegistration,
        response: cpky::RegisterPublicKeyCredential,
    ) -> Result<Record> {
        let _guard = crate::storage::member_lock(self.storage.community(), state.user).await;
        async {
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
        }
        .await
    }

    /// Account-first login; discoverable login remains a cpky integration issue.
    pub async fn begin_login(
        &self,
        user: Uuid,
    ) -> Result<(cpky::RequestChallengeResponse, PendingLogin)> {
        async {
            self.now()?;
            // cpky supplies the same coarse refusal for unknown or keyless users.

            let keys = self.passkeys.clone();
            let (challenge, pending) = blocking(move || keys.start_authentication(user)).await?;
            Ok((challenge, PendingLogin { user, pending }))
        }
        .await
    }

    /// Commit cpky's counter checks and return authenticated enrolment to the lobby.
    /// This does not extend a lease or record a login date.
    pub async fn finish_login(
        &self,
        state: PendingLogin,
        response: cpky::PublicKeyCredential,
    ) -> Result<Login> {
        async {
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
        }
        .await
    }

    /// Trusted service lookup, including expiry, lost registration receipts and
    /// current legal restrictions. Use `resume` for a member-facing endpoint.
    pub async fn enrolment_state(&self, user: Uuid) -> Result<Record> {
        let _guard = crate::storage::member_lock(self.storage.community(), user).await;
        self.sync(user, self.now()?).await
    }

    /// Resume the stable pseudonym binding after a committed cpky authentication.
    pub async fn resume(&self, auth: &Authentication) -> Result<Record> {
        self.authenticated(auth, self.now()?).await
    }

    /// Validate a candidate and check the actual register's reservation/lease state.
    /// Callers must throttle this unauthenticated lookup and supply current reserved names.
    pub async fn is_handle_available(&self, handle: &str, reserved: &[String]) -> Result<bool> {
        let checked = cgrd::check_handle(handle, reserved).map_err(|_| Error::InvalidInput)?;
        async {
            Ok(self
                .register
                .is_handle_available(&checked.skeleton, date(self.now()?)?)
                .await?)
        }
        .await
    }

    /// Revalidate a session's exact credential, including immediate revocation.
    /// An opaque cpky authentication alone is not a renewable bearer capability.
    pub async fn session_is_active(
        &self,
        auth: &Authentication,
        credential: &cpky::CredentialID,
    ) -> Result<bool> {
        async {
            self.authenticated(auth, self.now()?).await?;
            Ok(self.credentials(auth.member()).await?.iter().any(|key| {
                key.credential_id() == credential
                    && credential == auth.credential_id()
                    && !key.is_revoked()
            }))
        }
        .await
    }

    /// Reserve a validated handle. The per-member task completes even if its
    /// caller disconnects; a failure leaves no durable lock to recover.
    pub async fn reserve_handle(
        &self,
        auth: &Authentication,
        handle: &str,
        reserved: &[String],
    ) -> Result<Record> {
        let checked = cgrd::check_handle(handle, reserved).map_err(|_| Error::InvalidInput)?;
        let guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        let m = self.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let now = m.now()?;
            let row = m.authenticated(&auth, now).await?;
            if !matches!(
                row.state(),
                State::PasskeyRegistered | State::HandleReserved | State::GatesInProgress
            ) {
                return Err(Error::Transition);
            }
            let receipt = m
                .register
                .reserve_handle(
                    crgs::Reservation {
                        member_id: row.member_id(),
                        handle: crgs::Handle::new(&checked.normalized, &checked.skeleton)?,
                        expires_at: date(row.expires_at().ok_or(Error::Transition)?)?,
                    },
                    date(now)?,
                )
                .await?;
            Ok(m.enrol
                .apply(&row, Event::HandleReserved(&receipt), now)
                .await?)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    /// Pure lobby: current facts and cplc's decision, without lifecycle writes.
    pub async fn lobby<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        auth: &Authentication,
        policy: &cplc::Policy<R, P, K>,
        snapshot: &cplc::VerifiedSnapshot,
        gates: &cgts::CheckedGates,
    ) -> Result<Lobby> {
        let now = self.now()?;
        let row = self.authenticated(auth, now).await?;
        let decision = policy
            .may(
                snapshot,
                crbk::Subject {
                    id: row.subject(),
                    membership: row.state().membership(),
                },
                &self.action,
                gates,
                now as u64,
            )
            .await
            .map_err(|_| Error::Policy)?;
        let one_passkey = self
            .credentials(row.user())
            .await?
            .iter()
            .filter(|key| !key.is_revoked())
            .count()
            == 1;
        let mut warnings = Vec::new();
        if let Some(deadline) = row.expires_at() {
            warnings.push(Warning::RegistrationExpires { deadline });
        }
        if one_passkey {
            warnings.push(Warning::AddSecondDeviceOrSyncedPasskey);
        }
        Ok(Lobby {
            enrolment: row,
            decision,
            warnings,
        })
    }

    /// Admit or renew from cplc's fresh decision over verified capabilities only.
    /// The bounded lease and coarse probation are owned by membership.
    ///
    /// ```compile_fail
    /// fn raw(snapshot: crbk::Snapshot, results: Vec<crbk::GateResult>) {
    ///     let _: &cplc::VerifiedSnapshot = &snapshot;
    ///     let _: &cgts::CheckedGates = &results;
    /// }
    /// ```
    pub async fn admit<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        auth: &Authentication,
        policy: &cplc::Policy<R, P, K>,
        snapshot: &cplc::VerifiedSnapshot,
        gates: &cgts::CheckedGates,
        lease: crgs::YearMonth,
    ) -> Result<Record> {
        let guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        let now = self.now()?;
        let row = self.authenticated(auth, now).await?;
        let decision = policy
            .may(
                snapshot,
                crbk::Subject {
                    id: row.subject(),
                    membership: row.state().membership(),
                },
                &self.action,
                gates,
                now as u64,
            )
            .await
            .map_err(|_| Error::Policy)?;
        if !decision.allowed {
            return Err(Error::Policy);
        }
        let current = date(now)?;
        let last = current
            .checked_add_months(chrono::Months::new(self.lease_months))
            .ok_or(Error::InvalidInput)?;
        if lease < crgs::YearMonth::new(current.year() as u16, current.month() as u8)?
            || lease > crgs::YearMonth::new(last.year() as u16, last.month() as u8)?
        {
            return Err(Error::InvalidInput);
        }
        let durations = crbk::MembershipSettings::from_snapshot(snapshot.settings())
            .map_err(|_| Error::Policy)?;
        let probation_until = cplc::day(now as u64)
            .checked_add(u64::from(durations.probation_days) * cplc::DAY)
            .ok_or(Error::InvalidInput)?;
        let m = self.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let _guard = guard;
            m.identity(&auth).await?;
            m.unrestricted(row.subject()).await?;
            let row = m
                .enrol
                .apply(&row, Event::PolicyEvaluated(&decision), now)
                .await?;
            let member = if m.register.member(&row.member_id()).await?.is_some() {
                m.register
                    .extend_lease(&row.member_id(), lease, date(now)?)
                    .await?
            } else {
                m.register
                    .admit(
                        crgs::Admission {
                            id: row.member_id(),
                            handle: m.current_handle(&row).await?.ok_or(Error::Transition)?,
                            role: crgs::Role::Member,
                            lease_end: lease,
                        },
                        date(now)?,
                    )
                    .await?
            };
            if member.handle.is_none() {
                return Err(Error::Transition);
            }
            // Policy is never reconstructed during recovery. A retry requires a
            // fresh cplc decision; a register row alone cannot readmit a lapse.
            m.unrestricted(row.subject()).await?;
            let row = m
                .enrol
                .apply(
                    &row,
                    Event::AdmissionRecorded {
                        member: &member,
                        decision: &decision,
                    },
                    now,
                )
                .await?;
            m.storage
                .initialize_probation(row.subject(), probation_until)
                .await?;
            m.storage
                .clear_passed_probation(row.subject(), now as u64)
                .await?;
            Ok(row)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    /// Explicit lapse; merely asking for the lobby never calls this transition.
    pub async fn lapse<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        auth: &Authentication,
        policy: &cplc::Policy<R, P, K>,
        snapshot: &cplc::VerifiedSnapshot,
        gates: &cgts::CheckedGates,
    ) -> Result<Record> {
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        let lobby = self.lobby(auth, policy, snapshot, gates).await?;
        if lobby.decision.allowed {
            return Err(Error::Policy);
        }
        Ok(self
            .enrol
            .apply(
                &lobby.enrolment,
                Event::PolicyEvaluated(&lobby.decision),
                self.now()?,
            )
            .await?)
    }

    /// Insert a device-created digest. The caller authorizes the schema field;
    /// values and salts never enter this API or permanent storage.
    pub async fn pin(
        &self,
        auth: &Authentication,
        field: &str,
        fingerprint: cpns::Fingerprint,
    ) -> Result<Pin> {
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        async {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self.pins.pin(row.subject(), field, fingerprint).await?)
        }
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
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        async {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self
                .pins
                .change(row.subject(), field, expected, replacement, token)
                .await?)
        }
        .await
    }

    /// Read the current fingerprint and revision, without access history.
    pub async fn get_pin(&self, auth: &Authentication, field: &str) -> Result<Option<Pin>> {
        async {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self.pins.get(row.subject(), field).await?)
        }
        .await
    }

    /// Read the current register record for credential issuance or the lobby.
    /// The outer service must validate the coarse lease before granting access.
    pub async fn member(&self, auth: &Authentication) -> Result<Option<crgs::Member>> {
        async {
            let row = self.authenticated(auth, self.now()?).await?;
            Ok(self.register.member(&row.member_id()).await?)
        }
        .await
    }

    /// Return the canonical reserved or admitted handle for the lobby.
    pub async fn handle(&self, auth: &Authentication) -> Result<Option<crgs::Handle>> {
        async {
            let row = self.authenticated(auth, self.now()?).await?;
            self.current_handle(&row).await
        }
        .await
    }

    /// Revoke one owned credential. Losing the last live credential releases the
    /// lifecycle immediately; crgs retains its existing coarse handle deadline.
    pub async fn revoke_passkey(
        &self,
        auth: &Authentication,
        credential: cpky::CredentialID,
    ) -> Result<Record> {
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        async {
            let row = self.authenticated(auth, self.now()?).await?;
            let keys = self.passkeys.clone();
            let user = row.user();
            self.storage.signal_revocation(row.subject()).await?;
            blocking(move || keys.revoke(user, &credential)).await?;
            self.release_if_lost(row, self.now()?).await
        }
        .await
    }

    /// Trusted lost-key maintenance. Refuses while any credential remains live.
    /// Physical loss cannot be inferred: the service must first revoke the keys
    /// through an authorized device protocol. There is no recovery override.
    pub async fn release(&self, user: Uuid) -> Result<Record> {
        let _guard = crate::storage::member_lock(self.storage.community(), user).await;
        async {
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
        }
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
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        async {
            self.identity(auth).await?;
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
            self.storage.signal_revocation(row.subject()).await?;
            self.legal.self_ban(order).await?;
            self.sync(row.user(), self.now()?).await
        }
        .await
    }

    /// Bounded pending expiry, claim cleanup and crgs retention release, serialized
    /// with every registration/admission. Call periodically even without logins.
    pub async fn maintain(&self, limit: usize) -> Result<()> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::InvalidInput);
        }
        async {
            let now = self.now()?;
            for row in self.enrol_store.due(now / 86400, limit).await? {
                let _guard =
                    crate::storage::member_lock(self.storage.community(), row.user()).await;
                self.sync(row.user(), now).await?;
            }
            self.enrol.cleanup(self.register.as_ref(), limit).await?;
            self.register.release_expired(date(now)?, limit).await?;
            self.storage.prune_probation(now as u64, limit).await?;
            Ok(())
        }
        .await
    }

    fn now(&self) -> Result<i64> {
        let now = self.clock.now()?;
        date(now)?;
        Ok(now)
    }
    async fn identity(&self, auth: &Authentication) -> Result<()> {
        if auth.community() != self.storage.community() {
            Err(Error::Identity)
        } else if !self
            .credentials(auth.member())
            .await?
            .iter()
            .any(|key| key.credential_id() == auth.credential_id() && !key.is_revoked())
        {
            Err(Error::Passkey)
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
        let reservation = self.register.reservation(&row.member_id()).await?;
        Ok(reservation.map(|reservation| reservation.handle))
    }
    async fn unrestricted(&self, subject: &str) -> Result<()> {
        match self.legal.check_action(subject, &self.action).await? {
            clbs::State::Green => Ok(()),
            clbs::State::Red(_) => Err(Error::Restricted),
        }
    }
    async fn authenticated(&self, auth: &Authentication, now: i64) -> Result<Record> {
        self.identity(auth).await?;
        let row = self.enrol.view(auth.member(), now).await?;
        self.check_record(&row)?;
        self.unrestricted(row.subject()).await?;
        if row.state().is_terminal() {
            return Err(Error::Transition);
        }
        Ok(row)
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
                self.storage.signal_revocation(row.subject()).await?;
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
}

impl<
    S: Storage + 'static,
    V: ChangeTokenVerifier + 'static,
    L: clbs::Verifier + 'static,
    C: clbs::Clock + 'static,
> cplc::MembershipSource for Membership<S, V, L, C>
{
    type Lease = tokio::sync::OwnedMutexGuard<()>;
    async fn membership(
        &self,
        member: &str,
        now: u64,
    ) -> cplc::Result<(cplc::MembershipFacts, Self::Lease)> {
        let read: Result<_> = async {
            let now_i64 = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
            if self.now()? != now_i64 {
                return Err(Error::InvalidInput);
            }
            let row = self
                .enrol_store
                .load_subject(member)
                .await?
                .ok_or(Error::Transition)?;
            let guard = crate::storage::member_lock(self.storage.community(), row.user()).await;
            let row = self.enrol.view(row.user(), now_i64).await?;
            self.unrestricted(row.subject()).await?;
            if row.state() != State::Admitted
                || !self
                    .credentials(row.user())
                    .await?
                    .iter()
                    .any(|key| !key.is_revoked())
            {
                return Err(Error::Transition);
            }
            if self.storage.revocation_pending(member).await? {
                return Err(Error::Restricted);
            }
            self.storage.clear_passed_probation(member, now).await?;
            let probation_until = self
                .storage
                .probation(member)
                .await?
                .ok_or(Error::Transition)?;
            let registered = self
                .register
                .member(&row.member_id())
                .await?
                .ok_or(Error::Transition)?;
            if registered.handle.is_none() {
                return Err(Error::Transition);
            }
            let start = chrono::NaiveDate::from_ymd_opt(
                registered.lease_end.year().into(),
                registered.lease_end.month().into(),
                1,
            )
            .ok_or(Error::InvalidInput)?;
            let end = start
                .checked_add_months(chrono::Months::new(1))
                .ok_or(Error::InvalidInput)?;
            let lease_end = end
                .and_hms_opt(0, 0, 0)
                .ok_or(Error::InvalidInput)?
                .and_utc()
                .timestamp();
            Ok((
                cplc::MembershipFacts {
                    community: self.storage.community().into(),
                    member: member.into(),
                    state: row.state().membership(),
                    probation_until,
                    lease_end: lease_end as u64,
                },
                guard,
            ))
        }
        .await;
        read.map_err(|_| cplc::Error::Invalid("membership source unavailable"))
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
