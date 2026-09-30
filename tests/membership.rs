//! Real WebAuthn, register, enrolment, pin and self-ban integration tests.
mod common;
use cmbr::{Error, Storage, cnrl::State, cpky, cpns};
use common::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

#[tokio::test(flavor = "multi_thread")]
async fn complete_membership_round_trip() {
    let (_dir, db) = temporary().await;
    let facade = facade(&db, "a", Clock::new());
    let (mut device, auth) = pending(&facade, "a").await;
    let proof = test_gate("a", SUBJECT);
    assert_eq!(
        facade
            .admit(&auth.authentication, &policy("a"), &[], handle(), lease())
            .await,
        Err(Error::Policy)
    );
    let admitted = facade
        .admit(
            &auth.authentication,
            &policy("a"),
            std::slice::from_ref(&proof),
            handle(),
            lease(),
        )
        .await
        .unwrap();
    assert_eq!(admitted.state(), State::Admitted);
    assert_eq!(
        facade
            .admit(
                &auth.authentication,
                &policy("a"),
                std::slice::from_ref(&proof),
                handle(),
                lease()
            )
            .await
            .unwrap(),
        admitted
    );
    assert_eq!(facade.resume(&auth.authentication).await.unwrap(), admitted);
    let next = login(&facade, &mut device, USER).await;
    assert_eq!(next.enrolment, admitted);
    assert_eq!(
        facade
            .lapse(&next.authentication, &policy("a"), &[])
            .await
            .unwrap()
            .state(),
        State::Lapsed
    );
    assert_eq!(
        facade
            .admit(
                &next.authentication,
                &policy("a"),
                &[proof],
                handle(),
                lease()
            )
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    assert_eq!(facade.release(USER).await, Err(Error::Transition));
    assert!(facade.begin_registration(USER, SUBJECT).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn pins_require_exact_spent_binding_and_reject_replays() {
    let (_dir, db) = temporary().await;
    let facade = facade(&db, "a", Clock::new());
    let (_, auth) = pending(&facade, "a").await;
    let old_salt = cpns::Salt::from_bytes(vec![1; 32]).unwrap();
    let new_salt = cpns::Salt::from_bytes(vec![2; 32]).unwrap();
    let original = cpns::fingerprint(b"synthetic-value", &old_salt);
    let replacement = cpns::fingerprint(b"synthetic-value", &new_salt);
    let pin = facade
        .pin(&auth.authentication, "restricted", original)
        .await
        .unwrap();
    assert_eq!(
        facade
            .pin(&auth.authentication, "restricted", original)
            .await,
        Err(Error::Pin)
    );
    let mut token = Spent {
        community: "wrong".into(),
        member: SUBJECT.into(),
        field: "restricted".into(),
        expected: pin,
        replacement,
    };
    assert_eq!(
        facade
            .change_pin(&auth.authentication, "restricted", pin, replacement, &token)
            .await,
        Err(Error::Pin)
    );
    token.community = "a".into();
    let changed = facade
        .change_pin(&auth.authentication, "restricted", pin, replacement, &token)
        .await
        .unwrap();
    assert_eq!(changed.revision, pin.revision + 1);
    assert_eq!(
        facade
            .change_pin(&auth.authentication, "restricted", pin, replacement, &token)
            .await,
        Err(Error::Pin)
    );
    assert_eq!(
        facade
            .get_pin(&auth.authentication, "restricted")
            .await
            .unwrap(),
        Some(changed)
    );
    assert!(cpns::check_opening(
        &changed.fingerprint,
        b"synthetic-value",
        &new_salt
    ));
    assert!(!cpns::check_opening(
        &changed.fingerprint,
        b"synthetic-value",
        &old_salt
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_community_handle_and_registration_conflicts_fail_closed() {
    let (_dir, db) = temporary().await;
    let a = facade(&db, "a", Clock::new());
    let b = facade(&db, "b", Clock::new());
    let mut first = register(&a, USER, SUBJECT).await;
    let auth = login(&a, &mut first, USER).await;
    assert_eq!(b.resume(&auth.authentication).await, Err(Error::Identity));
    assert!(
        a.begin_registration(USER, "different-pseudonym")
            .await
            .is_err()
    );
    assert!(
        a.begin_registration(cpky::Uuid::from_u128(2), SUBJECT)
            .await
            .is_err()
    );
    assert!(
        a.reserve_handle(&auth.authentication, "tiny", &[])
            .await
            .is_err()
    );
    assert!(
        a.reserve_handle(&auth.authentication, HANDLE, &[HANDLE.into()])
            .await
            .is_err()
    );
    a.reserve_handle(&auth.authentication, HANDLE, &[])
        .await
        .unwrap();
    let mut second = register(&a, cpky::Uuid::from_u128(3), "second-pseudonym").await;
    let other = login(&a, &mut second, cpky::Uuid::from_u128(3)).await;
    assert_eq!(
        a.reserve_handle(&other.authentication, HANDLE, &[]).await,
        Err(Error::Register)
    );
    assert!(
        !cmbr::LibsqlStorage::new(&db, "a")
            .unwrap()
            .load()
            .await
            .unwrap()
            .is_busy()
    );
    let mut separate = register(&b, USER, SUBJECT).await;
    let separate = login(&b, &mut separate, USER).await;
    b.reserve_handle(&separate.authentication, HANDLE, &[])
        .await
        .unwrap();
    assert_eq!(
        a.lobby(&auth.authentication, &policy("b"), &[]).await,
        Err(Error::Identity)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_maintenance_frees_pending_handle_and_never_revives_identity() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let facade = facade(&db, "a", clock.clone());
    let (_, auth) = pending(&facade, "a").await;
    let deadline = facade
        .resume(&auth.authentication)
        .await
        .unwrap()
        .expires_at()
        .unwrap();
    clock.set(deadline);
    facade.maintain(20).await.unwrap();
    assert_eq!(
        facade.enrolment_state(USER).await.unwrap().state(),
        State::Expired
    );
    assert_eq!(
        facade.resume(&auth.authentication).await,
        Err(Error::Transition)
    );
    assert!(facade.begin_registration(USER, SUBJECT).await.is_err());
    let mut next = register(&facade, cpky::Uuid::from_u128(2), "another-subject").await;
    let next = login(&facade, &mut next, cpky::Uuid::from_u128(2)).await;
    facade
        .reserve_handle(&next.authentication, HANDLE, &[])
        .await
        .unwrap();
    assert_eq!(facade.maintain(0).await, Err(Error::InvalidInput));
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmed_self_ban_survives_reopen_and_cannot_be_bypassed() {
    let (dir, db) = temporary().await;
    let a = facade(&db, "a", Clock::new());
    let (_, auth) = pending(&a, "a").await;
    let order = ban("a");
    let mut bad = ban("a");
    bad.proof[0] ^= 1;
    assert_eq!(
        a.self_ban(&auth.authentication, &bad).await,
        Err(Error::Restricted)
    );
    // A rejected confirmation leaves the coordinator available.
    a.recover_after_quiescence().await.unwrap();
    assert_eq!(
        a.self_ban(&auth.authentication, &order)
            .await
            .unwrap()
            .state(),
        State::Released
    );
    assert_eq!(
        a.self_ban(&auth.authentication, &order)
            .await
            .unwrap()
            .state(),
        State::Released
    );
    assert_eq!(a.resume(&auth.authentication).await, Err(Error::Restricted));
    assert!(
        a.begin_registration(cpky::Uuid::from_u128(50), SUBJECT)
            .await
            .is_err()
    );
    let reopened = open(
        &format!("file://{}", dir.path().join("members.db").display()),
        "",
    )
    .await;
    let b = facade(&reopened, "a", Clock::new());
    assert_eq!(
        b.enrolment_state(USER).await.unwrap().state(),
        State::Released
    );
    assert_eq!(b.resume(&auth.authentication).await, Err(Error::Restricted));
}

#[tokio::test(flavor = "multi_thread")]
async fn unverified_registration_and_wrong_instance_do_not_write_passkeys() {
    let (_dir, db) = temporary().await;
    let a = facade(&db, "a", Clock::new());
    let b = facade(&db, "a", Clock::new());
    let (challenge, pending) = a.begin_registration(USER, SUBJECT).await.unwrap();
    let mut device = SoftToken::new(true).unwrap().0;
    let response = device
        .perform_register(
            cpky::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    assert_eq!(
        b.finish_registration(pending, response).await,
        Err(Error::Passkey)
    );
    assert_eq!(
        a.enrolment_state(USER).await.unwrap().state(),
        State::Started
    );
    let (challenge, pending) = a.begin_registration(USER, SUBJECT).await.unwrap();
    let mut device = SoftToken::new(true).unwrap().0;
    // Let the fixture produce a UV-less registration despite the server's policy.
    let mut options = challenge.public_key;
    if let Some(selection) = &mut options.authenticator_selection {
        selection.user_verification =
            serde_json::from_value(serde_json::json!("discouraged")).unwrap();
    }
    let response = device
        .perform_register(cpky::Url::parse(ORIGIN).unwrap(), options, 300_000)
        .unwrap();
    assert_eq!(
        a.finish_registration(pending, response).await,
        Err(Error::Passkey)
    );
    assert_eq!(
        a.enrolment_state(USER).await.unwrap().state(),
        State::Started
    );
}
