#![allow(dead_code)]

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

pub mod resident;

use ckyh::Uuid;
use ed25519_dalek::{Signer, SigningKey};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub const USER: Uuid = Uuid::from_u128(1);
pub const SUBJECT: &str = "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101";
pub const ORIGIN: &str = "https://members.example.org";
pub const HANDLE: &str = "member_handle";

#[derive(Clone)]
pub struct Clock(pub Arc<AtomicI64>);
impl Clock {
    pub fn new() -> Self {
        Self(Arc::new(AtomicI64::new(now())))
    }
    pub fn set(&self, time: i64) {
        self.0.store(time, Ordering::SeqCst);
    }
}
impl clbs::Clock for Clock {
    fn now(&self) -> clbs::Result<i64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
pub fn now() -> i64 {
    "2026-09-30T12:00:00Z"
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap()
        .timestamp()
}
pub fn date(time: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(time, 0).unwrap()
}
pub fn handle() -> crgs::Handle {
    {
        let checked = cgrd::check_handle(HANDLE, &[]).unwrap();
        crgs::Handle::new(checked.normalized, checked.skeleton).unwrap()
    }
}
pub fn lease() -> crgs::YearMonth {
    crgs::YearMonth::new(2027, 9).unwrap()
}

// A real signature fixture at the external clbs verifier seam. Production must
// additionally enforce device approval, fresh intent and qualified legal authority.
pub struct Verify;
impl clbs::Verifier for Verify {
    async fn verify_legal(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
        verify(order)
    }
    async fn verify_self_ban(&self, order: &clbs::SignedOrder) -> clbs::Result<()> {
        verify(order)
    }
}
fn verify(order: &clbs::SignedOrder) -> clbs::Result<()> {
    let signature =
        ed25519_dalek::Signature::from_slice(&order.proof).map_err(|_| clbs::Error::Denied)?;
    SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .verify_strict(&order.order.signing_payload()?, &signature)
        .map_err(|_| clbs::Error::Denied)
}
pub fn ban(community: &str) -> clbs::SignedOrder {
    let order = clbs::Order {
        community: community.into(),
        id: "confirmed-self-ban".into(),
        subject: SUBJECT.into(),
        reference: "synthetic-member-confirmation".into(),
        entered_by: SUBJECT.into(),
        kind: clbs::OrderKind::SelfBan,
        scope: clbs::Scope::All,
        period: clbs::Period {
            starts_at: now(),
            ends_at: None,
        },
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    clbs::SignedOrder { order, proof }
}

pub type Facade = cmbr::Membership<cmbr::LibsqlStorage, Verify, Clock>;
pub fn config() -> cmbr::Config {
    cmbr::Config {
        pending_days: 2,
        lease_months: 12,
        membership_action: "membership".into(),
        release_period: crgs::ReleasePeriod::default(),
        rp_id: "members.example.org".into(),
        origins: vec![ckyh::Url::parse(ORIGIN).unwrap()],
    }
}
pub fn facade(db: &crlt::Db, community: &str, clock: Clock) -> Facade {
    cmbr::Membership::new(
        db,
        cmbr::LibsqlStorage::new(db, community).unwrap(),
        config(),
        Verify,
        clock,
    )
    .unwrap()
}
pub async fn open(url: &str, token: &str) -> crlt::Db {
    let mut config = crlt::Config::new(url, token);
    config.max_connections = 4;
    let db = crlt::Db::open(config).await.unwrap();
    let mut schemas = cmbr::SCHEMAS.to_vec();
    schemas.push(("cmbr-device-keys", cmbr::DEVICE_KEYS_SCHEMA));
    let migrations: Vec<_> = schemas
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
        .collect();
    db.migrate(&migrations).await.unwrap();
    db
}
pub async fn temporary() -> (tempfile::TempDir, crlt::Db) {
    let dir = tempfile::tempdir().unwrap();
    let db = open(
        &format!("file://{}", dir.path().join("members.db").display()),
        "",
    )
    .await;
    (dir, db)
}
pub async fn register(facade: &Facade, user: Uuid, subject: &str) -> SoftToken {
    let mut device = SoftToken::new(true).unwrap().0;
    let (mut challenge, pending) = facade.begin_registration(user, subject).await.unwrap();
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response = device
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    assert_eq!(
        facade
            .finish_registration(pending, response.into())
            .await
            .unwrap()
            .state(),
        cnrl::State::PasskeyRegistered
    );
    device
}
pub async fn login(facade: &Facade, device: &mut SoftToken, user: Uuid) -> cmbr::Login {
    // The software wallet retains IDs in its own fixture store, just as a real
    // wallet retains the registration response. This does not read server state.
    let cbor = serde_cbor_2::value::to_value(&*device).unwrap();
    let serde_cbor_2::Value::Map(fields) = cbor else {
        panic!("token map")
    };
    let tokens: std::collections::HashMap<Vec<u8>, Vec<u8>> = serde_cbor_2::value::from_value(
        fields[&serde_cbor_2::Value::Text("tokens".into())].clone(),
    )
    .unwrap();
    let id = tokens.keys().next().unwrap();
    let (challenge, pending) = facade.begin_login(user, id.clone().into()).await.unwrap();
    let response = device
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    facade.finish_login(pending, response.into()).await.unwrap()
}

// Development-only gate: no production provider or enabling feature exists.
pub fn test_gate(community: &str, subject: &str) -> crbk::GateResult {
    crbk::GateResult {
        gate: "development-test".into(),
        level: crbk::GateLevel::Community,
        subject: subject.into(),
        community: Some(community.into()),
        provider: "fixture".into(),
        valid_until: now() + 3600,
        proven_at: None,
    }
}
pub fn policy(community: &str) -> crbk::Snapshot {
    let proof = test_gate(community, SUBJECT);
    let action = crbk::ActionPolicy {
        all_of: vec![crbk::Requirement {
            gate: proof.gate.clone(),
            level: proof.level,
            provider: None,
        }],
        ..Default::default()
    };
    crbk::Snapshot {
        community: community.into(),
        kind: crbk::SnapshotKind::Settings,
        revision: 1,
        policy_epoch: 1,
        issued: now(),
        content: [
            (
                crbk::action_key("membership"),
                serde_json::to_value(action).unwrap(),
            ),
            (
                crbk::gate_key(proof.level, &proof.gate),
                serde_json::json!(true),
            ),
            (
                crbk::provider_key(proof.level, &proof.gate, &proof.provider),
                serde_json::json!(true),
            ),
        ]
        .into(),
    }
}
pub async fn pending(facade: &Facade, community: &str) -> (SoftToken, cmbr::Login) {
    let mut device = register(facade, USER, SUBJECT).await;
    let login = login(facade, &mut device, USER).await;
    facade
        .reserve_handle(&login.authentication, HANDLE, &[])
        .await
        .unwrap();
    let (row, decision) = facade
        .lobby_test(&login.authentication, &policy(community), &[])
        .await
        .unwrap();
    assert_eq!(row.state(), cnrl::State::HandleReserved);
    assert!(!decision.allowed);
    (device, login)
}

pub type Policy = cplc::Policy<crbk::MemoryStore, cplc::MemoryStore, cplc::csgn::MemoryStore>;
pub async fn verified_policy(snapshot: &crbk::Snapshot, at: i64) -> Policy {
    let mut book = crbk::Rulebook::default();
    for (key, value) in &snapshot.content {
        book.define(
            key,
            crbk::Setting {
                value_type: if key == &crbk::action_key("membership") {
                    crbk::SettingType::Policy
                } else if value.is_boolean() {
                    crbk::SettingType::Boolean
                } else {
                    crbk::SettingType::Integer
                },
                nullable: false,
                default: value.clone(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    }
    let signer = cplc::csgn::PersistentSigner::create(
        cplc::csgn::MemoryStore::default(),
        &snapshot.community,
        cplc::csgn::SecretKey::from_seed(&mut [18; 32]),
        cplc::day(at as u64),
        30 * cplc::DAY,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        crbk::MemoryStore::default(),
        cplc::MemoryStore::new(&snapshot.community).unwrap(),
        signer,
        cplc::Config {
            credential_action: "membership".into(),
            snapshot_validity: cplc::DAY,
        },
    )
    .await
    .unwrap();
    policy
        .schedule_rules(
            None,
            crbk::Change {
                rulebook: book,
                announced_at: at,
                effective_at: at,
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap();
    policy
}
struct FixtureGate(crbk::GateResult);
impl cgts::Gate for FixtureGate {
    type Input = ();
    fn descriptor(&self) -> cgts::Descriptor {
        cgts::Descriptor {
            gate: self.0.gate.clone(),
            level: self.0.level,
            provider: self.0.provider.clone(),
            steps: vec![cgts::Step {
                id: "fixture".into(),
                description: "Synthetic provider fixture".into(),
                input: "unit".into(),
            }],
        }
    }
    async fn verify(&self, context: cgts::Context<'_>, _: &()) -> cgts::Result<cgts::Proof> {
        if self.0.subject != context.subject
            || self.0.community.as_deref() != Some(&context.snapshot.community)
        {
            return Err(cgts::Error::Scope);
        }
        Ok(cgts::Proof::transient(self.0.valid_until))
    }
}
#[derive(Clone)]
struct NoOrders;
impl clbs::Verifier for NoOrders {
    async fn verify_legal(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}
pub async fn checked(
    snapshot: &cplc::VerifiedSnapshot,
    subject: &str,
    gates: &[crbk::GateResult],
    at: i64,
) -> cgts::CheckedGates {
    let keeper = cgts::Gatekeeper::new(
        cgts::MemoryStore::new(&snapshot.settings().community).unwrap(),
        cgts::LegalGate::new(
            clbs::MemoryStore::new(&snapshot.settings().community).unwrap(),
            NoOrders,
        ),
    )
    .unwrap();
    let context = cgts::Context {
        snapshot: snapshot.settings(),
        subject,
        action: "membership",
        now: at,
    };
    let mut checked = Vec::new();
    for gate in gates {
        checked.push(
            keeper
                .run(context, &FixtureGate(gate.clone()), &())
                .await
                .unwrap(),
        );
    }
    keeper.check(context, checked).await.unwrap()
}
pub trait TestApi {
    async fn admit_test(
        &self,
        auth: &ckyh::Authentication,
        raw: &crbk::Snapshot,
        gates: &[crbk::GateResult],
        lease: crgs::YearMonth,
    ) -> cmbr::Result<cnrl::Record>;
    async fn lobby_test(
        &self,
        auth: &ckyh::Authentication,
        raw: &crbk::Snapshot,
        gates: &[crbk::GateResult],
    ) -> cmbr::Result<(cnrl::Record, crbk::Decision)>;
    async fn lapse_test(
        &self,
        auth: &ckyh::Authentication,
        raw: &crbk::Snapshot,
        gates: &[crbk::GateResult],
    ) -> cmbr::Result<cnrl::Record>;
}
impl TestApi for Facade {
    async fn admit_test(
        &self,
        auth: &ckyh::Authentication,
        raw: &crbk::Snapshot,
        gates: &[crbk::GateResult],
        lease: crgs::YearMonth,
    ) -> cmbr::Result<cnrl::Record> {
        let row = self.resume(auth).await?;
        let mut policy = verified_policy(raw, now()).await;
        let snapshot = policy.verified_settings(now() as u64).await.unwrap();
        let gates = checked(&snapshot, row.subject(), gates, now()).await;
        self.admit(auth, &policy, &snapshot, &gates, lease).await
    }
    async fn lobby_test(
        &self,
        auth: &ckyh::Authentication,
        raw: &crbk::Snapshot,
        gates: &[crbk::GateResult],
    ) -> cmbr::Result<(cnrl::Record, crbk::Decision)> {
        let row = self.resume(auth).await?;
        let mut policy = verified_policy(raw, now()).await;
        let snapshot = policy.verified_settings(now() as u64).await.unwrap();
        let gates = checked(&snapshot, row.subject(), gates, now()).await;
        let lobby = self.lobby(auth, &policy, &snapshot, &gates).await?;
        Ok((lobby.enrolment, lobby.decision))
    }
    async fn lapse_test(
        &self,
        auth: &ckyh::Authentication,
        raw: &crbk::Snapshot,
        gates: &[crbk::GateResult],
    ) -> cmbr::Result<cnrl::Record> {
        let row = self.resume(auth).await?;
        let mut policy = verified_policy(raw, now()).await;
        let snapshot = policy.verified_settings(now() as u64).await.unwrap();
        let gates = checked(&snapshot, row.subject(), gates, now()).await;
        self.lapse(auth, &policy, &snapshot, &gates).await
    }
}
