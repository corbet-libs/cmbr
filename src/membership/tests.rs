use super::{DateTime, Error, State, Utc, Uuid, Warning, blocking, date};
use cnrl::Storage as _;
#[path = "../../tests/common/mod.rs"]
mod common;
use crate::Storage;
use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn last_key_revocation_releases_but_preserves_committed_retention() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, login) = pending(&m, "a").await;
    m.admit_test(
        &login.authentication,
        &policy("a"),
        &[test_gate("a", SUBJECT)],
        lease(),
    )
    .await
    .unwrap();
    let credential = m
        .credentials(USER)
        .await
        .unwrap()
        .pop()
        .unwrap()
        .credential_id()
        .clone();
    let released = m
        .revoke_passkey(&login.authentication, credential)
        .await
        .unwrap();
    assert_eq!(released.state(), State::Released);
    assert_eq!(m.resume(&login.authentication).await, Err(Error::Passkey));
    assert_eq!(m.release(USER).await.unwrap().state(), State::Released);
    assert!(
        !m.register
            .is_handle_available(handle().skeleton(), date(now()).unwrap())
            .await
            .unwrap()
    );
    let end = "2029-10-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    clock.set(end.timestamp());
    m.maintain(50).await.unwrap();
    assert!(
        m.register
            .is_handle_available(handle().skeleton(), end)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_passkey_receipt_survives_an_interrupted_registration() {
    use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (challenge, pending) = m.begin_registration(USER, SUBJECT).await.unwrap();
    let mut token = SoftToken::new(true).unwrap().0;
    let response = token
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                let mut request = challenge.public_key;
                request
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                request
            },
            300_000,
        )
        .unwrap();
    let keys = m.passkeys.clone();
    blocking(move || {
        keys.finish_registration(
            pending.pending,
            &response.into(),
            ckyh::CreationMonth::new(2026, 9).unwrap(),
        )
    })
    .await
    .unwrap();
    assert_eq!(
        m.enrolment_state(USER).await.unwrap().state(),
        State::PasskeyRegistered
    );
    assert_eq!(
        login(&m, &mut token, USER).await.enrolment.state(),
        State::PasskeyRegistered
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_cannot_resurrect_a_handle_due_for_release() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, login) = pending(&m, "a").await;
    m.admit_test(
        &login.authentication,
        &policy("a"),
        &[test_gate("a", SUBJECT)],
        lease(),
    )
    .await
    .unwrap();
    let late = "2029-10-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    clock.set(late.timestamp());
    let mut gate = test_gate("a", SUBJECT);
    gate.valid_until = late.timestamp() + 3600;
    assert_eq!(
        m.admit_test(
            &login.authentication,
            &policy("a"),
            &[gate],
            crgs::YearMonth::new(2030, 9).unwrap()
        )
        .await,
        Err(Error::Policy)
    );
    m.maintain(50).await.unwrap();
    assert_eq!(
        m.enrolment_state(USER).await.unwrap().state(),
        State::Released
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn different_members_log_in_and_read_lobbies_concurrently_without_writes() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let mut first = register(&m, USER, SUBJECT).await;
    let other = Uuid::from_u128(2);
    let mut second = register(&m, other, "second-subject").await;
    let (a, b) = tokio::join!(login(&m, &mut first, USER), login(&m, &mut second, other));
    m.reserve_handle(&a.authentication, HANDLE, &[])
        .await
        .unwrap();
    m.reserve_handle(&b.authentication, "another_handle", &[])
        .await
        .unwrap();
    let before_a = m.enrol_store.load(USER).await.unwrap();
    let before_b = m.enrol_store.load(other).await.unwrap();
    let snapshot = policy("a");
    let (a, b) = tokio::join!(
        m.lobby_test(&a.authentication, &snapshot, &[]),
        m.lobby_test(&b.authentication, &snapshot, &[])
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(before_a, m.enrol_store.load(USER).await.unwrap());
    assert_eq!(before_b, m.enrol_store.load(other).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_reservation_finishes_and_never_blocks_other_members() {
    let (_dir, db) = temporary().await;
    let community = "cancelled-reservation";
    let m = facade(&db, community, Clock::new());
    let mut first = register(&m, USER, SUBJECT).await;
    let auth = login(&m, &mut first, USER).await.authentication;
    let other = Uuid::from_u128(2);
    let mut second = register(&m, other, "second-subject").await;
    let second_auth = login(&m, &mut second, other).await.authentication;
    // The actual register transaction waits for this writer. Read operations use
    // other leases from the same pool and must not acquire the writer lock.
    let writer = db.community(community).unwrap().tx().await.unwrap();
    // This fixture has its own member lock. Poll through its uncontended
    // acquisition and task spawn before cancelling the caller's future.
    let mut reservation = Box::pin(m.reserve_handle(&auth, HANDLE, &[]));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(reservation.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(reservation);
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), m.resume(&second_auth))
            .await
            .unwrap()
            .is_ok()
    );
    drop(writer);
    // Queueing behind this member waits for the owned cross-leaf task to finish.
    let _guard = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::storage::member_lock(community, USER),
    )
    .await
    .unwrap();
    assert_eq!(
        m.enrol_store.load(USER).await.unwrap().unwrap().state(),
        State::HandleReserved
    );
    assert!(!m.is_handle_available(HANDLE, &[]).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_authentication_cannot_change_pins_or_revoke_the_remaining_key() {
    use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (_, login) = pending(&m, "a").await;
    // Provision a second real passkey through the owning leaf's authorized test seam.
    let keys = m.passkeys.clone();
    let (challenge, pending) = blocking(move || keys.start_registration(USER))
        .await
        .unwrap();
    let mut token = SoftToken::new(true).unwrap().0;
    let response = token
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                let mut request = challenge.public_key;
                request
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                request
            },
            300000,
        )
        .unwrap();
    let keys = m.passkeys.clone();
    let second = blocking(move || {
        keys.finish_registration(
            pending,
            &response.into(),
            ckyh::CreationMonth::new(2026, 9).unwrap(),
        )
    })
    .await
    .unwrap();
    let stolen = login.authentication.credential_id().clone();
    assert_eq!(
        m.revoke_passkey(&login.authentication, stolen)
            .await
            .unwrap()
            .state(),
        State::HandleReserved
    );
    assert_eq!(
        m.revoke_passkey(&login.authentication, second.credential_id().clone())
            .await,
        Err(Error::Passkey)
    );
    assert_eq!(
        m.get_pin(&login.authentication, "restricted").await,
        Err(Error::Passkey)
    );
    assert_eq!(
        m.session_is_active(&login.authentication, second.credential_id())
            .await,
        Err(Error::Passkey)
    );
    assert!(
        m.credentials(USER)
            .await
            .unwrap()
            .iter()
            .any(|key| key.credential_id() == second.credential_id() && !key.is_revoked())
    );
    let salt = cpns::Salt::from_bytes(vec![55; 32]).unwrap();
    let pin = crate::PinV2::seal(
        &cpns::FingerprintContext {
            community: "a",
            member: SUBJECT,
            field: "age",
        },
        b"34",
        &salt,
    );
    assert_eq!(
        m.pin(&login.authentication, "age", &pin).await,
        Err(Error::Passkey)
    );
    assert_eq!(
        m.change_pin(
            &login.authentication,
            "age",
            cpns::server::Pin {
                fingerprint: pin.fingerprint(),
                revision: 1
            },
            &pin,
            b"unspent"
        )
        .await,
        Err(Error::Passkey)
    );
    assert_eq!(m.revocations(10).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pure_lobby_keeps_admission_and_returns_irreversible_expiry_warnings() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (_, login) = pending(&m, "a").await;
    let mut policy = verified_policy(&policy("a"), now()).await;
    let snapshot = policy.verified_settings(now() as u64).await.unwrap();
    let empty = checked(&snapshot, SUBJECT, &[], now()).await;
    let lobby = m
        .lobby(&login.authentication, &policy, &snapshot, &empty)
        .await
        .unwrap();
    assert!(lobby.warnings.iter().any(|warning| matches!(warning, Warning::RegistrationExpires { deadline } if deadline % 86400 == 0)));
    assert!(
        lobby
            .warnings
            .contains(&Warning::AddSecondDeviceOrSyncedPasskey)
    );
    let gates = checked(&snapshot, SUBJECT, &[test_gate("a", SUBJECT)], now()).await;
    m.admit(&login.authentication, &policy, &snapshot, &gates, lease())
        .await
        .unwrap();
    let before = m.enrol_store.load(USER).await.unwrap().unwrap();
    let lobby = m
        .lobby(&login.authentication, &policy, &snapshot, &empty)
        .await
        .unwrap();
    assert!(!lobby.decision.allowed);
    assert_eq!(lobby.enrolment, before);
    assert_eq!(m.enrol_store.load(USER).await.unwrap().unwrap(), before);
    assert!(
        !lobby
            .warnings
            .iter()
            .any(|warning| matches!(warning, Warning::RegistrationExpires { .. }))
    );
    assert_eq!(
        m.storage.probation(SUBJECT).await.unwrap(),
        Some(Some(cplc::day(now() as u64) + 14 * cplc::DAY))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_verified_inputs_and_unbounded_leases_cannot_admit() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (_, login) = pending(&m, "a").await;
    let mut policy = verified_policy(&policy("a"), now()).await;
    let old = policy.verified_settings(now() as u64).await.unwrap();
    let gates = checked(&old, SUBJECT, &[test_gate("a", SUBJECT)], now()).await;
    assert_eq!(
        m.admit(
            &login.authentication,
            &policy,
            &old,
            &gates,
            crgs::YearMonth::new(9999, 12).unwrap()
        )
        .await,
        Err(Error::InvalidInput)
    );
    policy
        .publish(cplc::SnapshotKind::Settings, now() as u64)
        .await
        .unwrap();
    assert_eq!(
        m.admit(&login.authentication, &policy, &old, &gates, lease())
            .await,
        Err(Error::Policy)
    );
    let current = policy.verified_settings(now() as u64).await.unwrap();
    assert_eq!(
        m.admit(&login.authentication, &policy, &current, &gates, lease())
            .await,
        Err(Error::Policy)
    );
    assert_eq!(
        m.enrol_store.load(USER).await.unwrap().unwrap().state(),
        State::HandleReserved
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn clock_and_storage_errors_leave_no_operation_lock() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, login) = pending(&m, "a").await;
    clock.set(-1);
    assert!(
        m.reserve_handle(&login.authentication, HANDLE, &[])
            .await
            .is_err()
    );
    clock.set(now());
    m.reserve_handle(&login.authentication, HANDLE, &[])
        .await
        .unwrap();
    // Delete only the test's probation table to fail after the actual register
    // admission. The operation returns an error; sessions and retries stay live.
    let mut migrations: Vec<_> = crate::SCHEMAS
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, name, sql))
        .collect();
    migrations.push(crlt::Migration::new(
        7,
        "cmbr-device-keys",
        crate::DEVICE_KEYS_SCHEMA,
    ));
    migrations.push(crlt::Migration::new(
        8,
        "break-probation",
        "DROP TABLE cmbr_probation;",
    ));
    db.migrate(&migrations).await.unwrap();
    assert_eq!(
        m.admit_test(
            &login.authentication,
            &policy("a"),
            &[test_gate("a", SUBJECT)],
            lease()
        )
        .await,
        Err(Error::Unavailable)
    );
    assert!(m.resume(&login.authentication).await.is_ok());
    migrations.push(crlt::Migration::new(9,"restore-probation","CREATE TABLE cmbr_probation (community_id TEXT NOT NULL, subject TEXT NOT NULL, probation_until INTEGER, PRIMARY KEY (community_id, subject)) WITHOUT ROWID;"));
    db.migrate(&migrations).await.unwrap();
    assert!(
        m.admit_test(
            &login.authentication,
            &policy("a"),
            &[test_gate("a", SUBJECT)],
            lease()
        )
        .await
        .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn login_challenges_hide_membership_and_never_create_enrolment() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (_, login) = pending(&m, "a").await;
    let id = login.authentication.credential_id().clone();
    let (known, _) = m.begin_login(USER, id.clone()).await.unwrap();
    let unknown = Uuid::from_u128(987);
    let (absent, _) = m.begin_login(unknown, id).await.unwrap();
    let shape = |value: ckyh::RequestChallengeResponse| {
        let mut value = serde_json::to_value(value).unwrap();
        value["publicKey"]
            .as_object_mut()
            .unwrap()
            .remove("challenge");
        value
    };
    assert_eq!(shape(known), shape(absent));
    assert!(m.enrol_store.load(unknown).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_lapse_queues_durable_revocation_before_readmission() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "lapse-event", Clock::new());
    let (_, login) = pending(&m, "lapse-event").await;
    let mut policy = verified_policy(&policy("lapse-event"), now()).await;
    let snapshot = policy.verified_settings(now() as u64).await.unwrap();
    let green = checked(
        &snapshot,
        SUBJECT,
        &[test_gate("lapse-event", SUBJECT)],
        now(),
    )
    .await;
    m.admit(&login.authentication, &policy, &snapshot, &green, lease())
        .await
        .unwrap();
    assert!(m.revocations(10).await.unwrap().is_empty());
    let red = checked(&snapshot, SUBJECT, &[], now()).await;
    let row = m
        .lapse(&login.authentication, &policy, &snapshot, &red)
        .await
        .unwrap();
    assert_eq!(row.state(), State::Lapsed);
    let events = m.revocations(10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].member, SUBJECT);
    assert!(m.storage.revocation_pending(SUBJECT).await.unwrap());
    m.lapse(&login.authentication, &policy, &snapshot, &red)
        .await
        .unwrap();
    assert_eq!(m.revocations(10).await.unwrap(), events);
}

#[tokio::test(flavor = "multi_thread")]
async fn issuance_source_holds_live_authority_until_its_lease_is_released() {
    use cplc::MembershipSource;
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "source-lease", clock.clone());
    let (_, login) = pending(&m, "source-lease").await;
    assert!(m.membership(SUBJECT, now() as u64).await.is_err());
    m.admit_test(
        &login.authentication,
        &policy("source-lease"),
        &[test_gate("source-lease", SUBJECT)],
        lease(),
    )
    .await
    .unwrap();
    let (empty, guard) = m.membership(SUBJECT, now() as u64).await.unwrap();
    assert!(empty.authorized_devices.is_empty());
    drop(guard);
    assert!(
        m.authorize_device_key(&login.authentication, [0; 32])
            .await
            .is_err()
    );
    assert!(m.revocations(10).await.unwrap().is_empty());
    let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32])
        .verifying_key()
        .to_bytes();
    m.authorize_device_key(&login.authentication, key)
        .await
        .unwrap();
    assert!(m.revocations(10).await.unwrap().is_empty());
    for (member, at) in [
        ("unknown", now() as u64),
        (SUBJECT, now() as u64 + 1),
        (SUBJECT, u64::MAX),
    ] {
        assert!(m.membership(member, at).await.is_err());
    }
    let (facts, guard) = m.membership(SUBJECT, now() as u64).await.unwrap();
    assert_eq!(facts.community, "source-lease");
    assert_eq!(facts.member, SUBJECT);
    assert_eq!(facts.authorized_devices, vec![key]);
    assert_eq!(facts.lease_end % 86400, 0);
    assert!(facts.probation_until.is_some());
    // A competing removal cannot interleave with the held issuance lease.
    let mut removal = Box::pin(m.revoke_passkey(
        &login.authentication,
        login.authentication.credential_id().clone(),
    ));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(removal.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(removal);
    drop(guard);
    clock.set(now() + 20 * 86400);
    let (facts, guard) = m
        .membership(SUBJECT, (now() + 20 * 86400) as u64)
        .await
        .unwrap();
    assert!(facts.probation_until.is_none());
    assert_eq!(facts.authorized_devices, vec![key]);
    drop(guard);
    m.revoke_passkey(
        &login.authentication,
        login.authentication.credential_id().clone(),
    )
    .await
    .unwrap();
    assert!(
        m.membership(SUBJECT, (now() + 20 * 86400) as u64)
            .await
            .is_err()
    );
    assert_eq!(m.revocations(10).await.unwrap().len(), 1);
}
