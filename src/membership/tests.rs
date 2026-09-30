use super::*;
#[path = "../../tests/common/mod.rs"]
mod common;
use common::*;

async fn occupy(facade: &Facade, operation: Operation) -> Checkpoint {
    let idle = facade.storage.load().await.unwrap();
    let next = idle.next(Some(operation)).unwrap();
    facade.storage.compare_exchange(&idle, &next).await.unwrap();
    next
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_crash_is_reconciled_before_pending_expiry_after_reopen() {
    let (dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, login) = pending(&m, "a").await;
    let (before, verdict) = m
        .lobby(
            &login.authentication,
            &policy("a"),
            &[test_gate("a", SUBJECT)],
        )
        .await
        .unwrap();
    assert!(verdict.allowed);
    occupy(
        &m,
        Operation::Admission {
            before: before.clone(),
            lease_year: lease().year(),
            lease_month: lease().month(),
        },
    )
    .await;
    // The actual leaf transaction commits. Simulate process loss before its cnrl receipt.
    m.register
        .admit(
            crgs::Admission {
                id: before.member_id(),
                handle: handle(),
                role: crgs::Role::Member,
                lease_end: lease(),
            },
            date(now()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(m.maintain(10).await, Err(Error::Busy));
    assert_eq!(m.enrolment_state(USER).await, Err(Error::Busy));
    clock.set(before.expires_at().unwrap() + 1);
    let reopened = open(
        &format!("file://{}", dir.path().join("members.db").display()),
        "",
    )
    .await;
    let restarted = facade(&reopened, "a", clock);
    restarted.recover_after_quiescence().await.unwrap();
    restarted.recover_after_quiescence().await.unwrap();
    let current = restarted.enrolment_state(USER).await.unwrap();
    assert_eq!(current.state(), State::Admitted);
    assert_eq!(current.expires_at(), None);
    restarted.maintain(20).await.unwrap();
    assert!(
        restarted
            .register
            .member(&current.member_id())
            .await
            .unwrap()
            .unwrap()
            .handle
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uncommitted_admission_never_creates_a_member_during_recovery() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, auth) = pending(&m, "a").await;
    let before = m.resume(&auth.authentication).await.unwrap();
    occupy(
        &m,
        Operation::Admission {
            before: before.clone(),
            lease_year: lease().year(),
            lease_month: lease().month(),
        },
    )
    .await;
    clock.set(before.expires_at().unwrap());
    m.recover_after_quiescence().await.unwrap();
    assert_eq!(
        m.enrolment_state(USER).await.unwrap().state(),
        State::Expired
    );
    assert!(
        m.register
            .member(&before.member_id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reservation_crash_resumes_or_cancels_at_the_fixed_deadline() {
    for expire in [false, true] {
        let (_dir, db) = temporary().await;
        let clock = Clock::new();
        let m = facade(&db, "a", clock.clone());
        register(&m, USER, SUBJECT).await;
        let before = m.enrolment_state(USER).await.unwrap();
        occupy(
            &m,
            Operation::Reservation {
                before: before.clone(),
                display: HANDLE.into(),
                skeleton: HANDLE.into(),
            },
        )
        .await;
        m.register
            .reserve_handle(
                crgs::Reservation {
                    member_id: before.member_id(),
                    handle: handle(),
                    expires_at: date(before.expires_at().unwrap()).unwrap(),
                },
                date(now()).unwrap(),
            )
            .await
            .unwrap();
        if expire {
            clock.set(before.expires_at().unwrap());
        }
        m.recover_after_quiescence().await.unwrap();
        let row = m.enrolment_state(USER).await.unwrap();
        assert_eq!(
            row.state(),
            if expire {
                State::Expired
            } else {
                State::HandleReserved
            }
        );
        if expire {
            assert!(
                m.register
                    .is_handle_available(HANDLE, date(before.expires_at().unwrap()).unwrap())
                    .await
                    .unwrap()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn last_key_revocation_releases_but_preserves_committed_retention() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, login) = pending(&m, "a").await;
    m.admit(
        &login.authentication,
        &policy("a"),
        &[test_gate("a", SUBJECT)],
        handle(),
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
    assert_eq!(
        m.resume(&login.authentication).await,
        Err(Error::Transition)
    );
    assert_eq!(m.release(USER).await.unwrap().state(), State::Released);
    assert!(
        !m.register
            .is_handle_available(HANDLE, date(now()).unwrap())
            .await
            .unwrap()
    );
    let end = "2029-10-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
    clock.set(end.timestamp());
    m.maintain(50).await.unwrap();
    assert!(m.register.is_handle_available(HANDLE, end).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn libsql_instances_contend_on_the_same_durable_slot() {
    let (dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let second = open(
        &format!("file://{}", dir.path().join("members.db").display()),
        "",
    )
    .await;
    let other = facade(&second, "a", Clock::new());
    let idle = m.storage.load().await.unwrap();
    let active = idle.next(Some(Operation::Busy)).unwrap();
    let (first, second) = tokio::join!(
        m.storage.compare_exchange(&idle, &active),
        other.storage.compare_exchange(&idle, &active)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(other.maintain(10).await, Err(Error::Busy));
    // Both simulated writers have stopped before recovery is allowed.
    other.recover_after_quiescence().await.unwrap();
    other.maintain(10).await.unwrap();
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
            cpky::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    occupy(&m, Operation::Busy).await;
    let keys = m.passkeys.clone();
    blocking(move || {
        keys.finish_registration(
            pending.pending,
            &response,
            cpky::CreationMonth::new(2026, 9).unwrap(),
        )
    })
    .await
    .unwrap();
    m.recover_after_quiescence().await.unwrap();
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
async fn corrupt_storage_fails_closed_without_echoing_sensitive_data() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    m.maintain(1).await.unwrap();
    let scope = db.community("a").unwrap();
    let mut tx = scope.tx().await.unwrap();
    tx.execute(
        "UPDATE cmbr_coordination SET payload = ?1 WHERE slot = 1",
        ["sensitive-invalid-json"],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let error = m.maintain(1).await.unwrap_err();
    assert_eq!(error, Error::Unavailable);
    assert!(!format!("{error:?} {error}").contains("sensitive-invalid-json"));
}
