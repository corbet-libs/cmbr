#![allow(dead_code)]

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use cmbr::{clbs, cpky, cpns, crbk, crgs, crlt};
use cpky::Uuid;
use ed25519_dalek::{Signer, SigningKey};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub const USER: Uuid = Uuid::from_u128(1);
pub const SUBJECT: &str = "community-pseudonym";
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
    crgs::Handle::new(HANDLE, HANDLE).unwrap()
}
pub fn lease() -> crgs::YearMonth {
    crgs::YearMonth::new(2027, 9).unwrap()
}

// Test-only external authorization receipt. This fixture exercises exact cpns
// binding; it is deliberately not a cblc proof or production spend adapter.
pub struct Spent {
    pub community: String,
    pub member: String,
    pub field: String,
    pub expected: cpns::server::Pin,
    pub replacement: cpns::Fingerprint,
}
pub struct Spends;
impl cpns::server::ChangeTokenVerifier for Spends {
    type Token = Spent;
    async fn verify_spent(
        &self,
        change: &cpns::server::Change<'_>,
        spent: &Spent,
    ) -> Result<(), cpns::server::TokenRejected> {
        if change.community == spent.community
            && change.member == spent.member
            && change.field == spent.field
            && change.expected == spent.expected
            && change.replacement == spent.replacement
        {
            Ok(())
        } else {
            Err(cpns::server::TokenRejected)
        }
    }
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

pub type Facade = cmbr::Membership<cmbr::LibsqlStorage, Spends, Verify, Clock>;
pub fn config() -> cmbr::Config {
    cmbr::Config {
        pending_days: 2,
        membership_action: "membership".into(),
        release_period: crgs::ReleasePeriod::default(),
        rp_id: "members.example.org".into(),
        origins: vec![cpky::Url::parse(ORIGIN).unwrap()],
    }
}
pub fn facade(db: &crlt::Db, community: &str, clock: Clock) -> Facade {
    cmbr::Membership::new(
        db,
        cmbr::LibsqlStorage::new(db, community).unwrap(),
        config(),
        Spends,
        Verify,
        clock,
    )
    .unwrap()
}
pub async fn open(url: &str, token: &str) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    let migrations: Vec<_> = cmbr::SCHEMAS
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
    let (challenge, pending) = facade.begin_registration(user, subject).await.unwrap();
    let response = device
        .perform_register(
            cpky::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    assert_eq!(
        facade
            .finish_registration(pending, response)
            .await
            .unwrap()
            .state(),
        cmbr::cnrl::State::PasskeyRegistered
    );
    device
}
pub async fn login(facade: &Facade, device: &mut SoftToken, user: Uuid) -> cmbr::Login {
    let (challenge, pending) = facade.begin_login(user).await.unwrap();
    let response = device
        .perform_auth(
            cpky::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    facade.finish_login(pending, response).await.unwrap()
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
        .lobby(&login.authentication, &policy(community), &[])
        .await
        .unwrap();
    assert_eq!(row.state(), cmbr::cnrl::State::GatesInProgress);
    assert!(!decision.allowed);
    (device, login)
}
