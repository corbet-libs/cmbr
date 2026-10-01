//! Real WebAuthn, register, enrolment, pin and self-ban integration tests.
mod common;
use cmbr::Error;
use cnrl::State;
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
            .admit_test(&auth.authentication, &policy("a"), &[], lease())
            .await,
        Err(Error::Policy)
    );
    let admitted = facade
        .admit_test(
            &auth.authentication,
            &policy("a"),
            std::slice::from_ref(&proof),
            lease(),
        )
        .await
        .unwrap();
    assert_eq!(admitted.state(), State::Admitted);
    assert_eq!(
        facade
            .admit_test(
                &auth.authentication,
                &policy("a"),
                std::slice::from_ref(&proof),
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
            .lapse_test(&next.authentication, &policy("a"), &[])
            .await
            .unwrap()
            .state(),
        State::Lapsed
    );
    assert_eq!(
        facade
            .admit_test(&next.authentication, &policy("a"), &[proof], lease())
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    assert_eq!(facade.release(USER).await, Err(Error::Transition));
    assert!(facade.begin_registration(USER, SUBJECT).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn unproven_pin_spends_cannot_change_state_even_after_restart() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (_, auth) = pending(&m, "a").await;
    let old_salt = cpns::Salt::from_bytes(vec![1; 32]).unwrap();
    let new_salt = cpns::Salt::from_bytes(vec![2; 32]).unwrap();
    let context = cpns::FingerprintContext {
        community: "a",
        member: SUBJECT,
        field: "restricted",
    };
    let original = cmbr::PinV2::seal(&context, b"synthetic-value", &old_salt);
    let replacement = cmbr::PinV2::seal(&context, b"synthetic-value", &new_salt);
    let pin = m
        .pin(&auth.authentication, "restricted", &original)
        .await
        .unwrap();
    assert_eq!(
        m.pin(&auth.authentication, "restricted", &original).await,
        Err(Error::Pin)
    );
    for evidence in [b"unspent".as_slice(), b"signed-acceptance", b"replay"] {
        assert!(matches!(
            m.change_pin(
                &auth.authentication,
                "restricted",
                pin,
                &replacement,
                evidence
            )
            .await,
            Err(Error::ExtensionsUnavailable)
        ));
        assert_eq!(
            m.get_pin(&auth.authentication, "restricted").await.unwrap(),
            Some(pin)
        );
    }
    drop(m);
    let m = facade(&db, "a", Clock::new());
    assert!(matches!(
        m.change_pin(
            &auth.authentication,
            "restricted",
            pin,
            &replacement,
            b"replay"
        )
        .await,
        Err(Error::ExtensionsUnavailable)
    ));
    assert_eq!(
        m.get_pin(&auth.authentication, "restricted").await.unwrap(),
        Some(pin)
    );
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
        a.begin_registration(ckyh::Uuid::from_u128(2), SUBJECT)
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
    let mut second = register(&a, ckyh::Uuid::from_u128(3), "second-pseudonym").await;
    let other = login(&a, &mut second, ckyh::Uuid::from_u128(3)).await;
    assert_eq!(
        a.reserve_handle(&other.authentication, HANDLE, &[]).await,
        Err(Error::Register)
    );
    let mut separate = register(&b, USER, SUBJECT).await;
    let separate = login(&b, &mut separate, USER).await;
    b.reserve_handle(&separate.authentication, HANDLE, &[])
        .await
        .unwrap();
    assert!(
        a.lobby_test(&auth.authentication, &policy("b"), &[])
            .await
            .is_err()
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
    let mut next = register(&facade, ckyh::Uuid::from_u128(2), "another-subject").await;
    let next = login(&facade, &mut next, ckyh::Uuid::from_u128(2)).await;
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
    assert!(a.resume(&auth.authentication).await.is_ok());
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
        a.begin_registration(ckyh::Uuid::from_u128(50), SUBJECT)
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
    let (mut challenge, pending) = a.begin_registration(USER, SUBJECT).await.unwrap();
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let mut device = SoftToken::new(true).unwrap().0;
    let response = device
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = challenge.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    assert_eq!(
        b.finish_registration(pending, response.into()).await,
        Err(Error::Passkey)
    );
    assert_eq!(
        a.enrolment_state(USER).await.unwrap().state(),
        State::Started
    );
    let (mut challenge, pending) = a.begin_registration(USER, SUBJECT).await.unwrap();
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let mut device = SoftToken::new(true).unwrap().0;
    // Let the fixture produce a UV-less registration despite the server's policy.
    let mut options = challenge.public_key;
    if let Some(selection) = &mut options.authenticator_selection {
        selection.user_verification =
            serde_json::from_value(serde_json::json!("discouraged")).unwrap();
    }
    let response = device
        .perform_register(ckyh::Url::parse(ORIGIN).unwrap(), options, 300_000)
        .unwrap();
    assert_eq!(
        a.finish_registration(pending, response.into()).await,
        Err(Error::Passkey)
    );
    assert_eq!(
        a.enrolment_state(USER).await.unwrap().state(),
        State::Started
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn handle_availability_and_exact_session_revocation_use_real_leaves() {
    let (_dir, db) = temporary().await;
    let a = facade(&db, "a", Clock::new());
    let b = facade(&db, "b", Clock::new());
    assert!(a.is_handle_available(HANDLE, &[]).await.unwrap());
    assert!(a.is_handle_available("tiny", &[]).await.is_err());
    assert!(
        a.is_handle_available(HANDLE, &[HANDLE.into()])
            .await
            .is_err()
    );
    let (_, auth) = pending(&a, "a").await;
    assert!(!a.is_handle_available(HANDLE, &[]).await.unwrap());
    assert!(b.is_handle_available(HANDLE, &[]).await.unwrap());
    let unknown: ckyh::CredentialID = vec![0; 32].into();
    assert!(
        !a.session_is_active(&auth.authentication, &unknown)
            .await
            .unwrap()
    );
    assert!(
        b.session_is_active(&auth.authentication, &unknown)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn additional_device_preserves_membership_and_survives_original_removal() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "a", Clock::new());
    let (_, first) = pending(&m, "a").await;
    let admitted = m
        .admit_test(
            &first.authentication,
            &policy("a"),
            &[test_gate("a", SUBJECT)],
            lease(),
        )
        .await
        .unwrap();
    let (options, state) = m
        .begin_additional_registration(&first.authentication)
        .await
        .unwrap();
    let mut second = SoftToken::new(true).unwrap().0;
    let response = second
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = options.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    let added = m
        .finish_additional_registration(&first.authentication, state, response.into())
        .await
        .unwrap();
    assert_eq!(added.member(), USER);
    assert_eq!(m.resume(&first.authentication).await.unwrap(), admitted);
    let survivor = login(&m, &mut second, USER).await;
    assert_eq!(survivor.enrolment, admitted);
    m.revoke_passkey(
        &survivor.authentication,
        first.authentication.credential_id().clone(),
    )
    .await
    .unwrap();
    assert!(m.resume(&first.authentication).await.is_err());
    assert!(
        m.begin_additional_registration(&first.authentication)
            .await
            .is_err()
    );
    assert!(
        m.session_is_active(&survivor.authentication, added.credential_id())
            .await
            .unwrap()
    );
    drop(m);
    let m = facade(&db, "a", Clock::new());
    let survivor = login(&m, &mut second, USER).await;
    assert_eq!(survivor.enrolment, admitted);
    assert_eq!(
        m.handle(&survivor.authentication)
            .await
            .unwrap()
            .unwrap()
            .display(),
        HANDLE
    );
    assert_eq!(
        m.revoke_passkey(&survivor.authentication, added.credential_id().clone())
            .await
            .unwrap()
            .state(),
        State::Released
    );
    assert!(
        m.begin_registration(ckyh::Uuid::from_u128(9), SUBJECT)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn additional_registration_rejects_substitution_revocation_and_expiry() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "a", clock.clone());
    let (_, first) = pending(&m, "a").await;
    let mut other_device = register(&m, ckyh::Uuid::from_u128(2), "another-member").await;
    let other = login(&m, &mut other_device, ckyh::Uuid::from_u128(2)).await;
    let (options, state) = m
        .begin_additional_registration(&first.authentication)
        .await
        .unwrap();
    let response = SoftToken::new(true)
        .unwrap()
        .0
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = options.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    assert!(matches!(
        m.finish_additional_registration(&other.authentication, state, response.into())
            .await,
        Err(Error::Identity)
    ));
    let foreign = facade(&db, "b", clock.clone());
    assert!(
        foreign
            .begin_additional_registration(&first.authentication)
            .await
            .is_err()
    );
    let (options, state) = m
        .begin_additional_registration(&other.authentication)
        .await
        .unwrap();
    let response = SoftToken::new(true)
        .unwrap()
        .0
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = options.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();
    m.revoke_passkey(
        &other.authentication,
        other.authentication.credential_id().clone(),
    )
    .await
    .unwrap();
    assert!(
        m.finish_additional_registration(&other.authentication, state, response.into())
            .await
            .is_err()
    );
    let (options, state) = m
        .begin_additional_registration(&first.authentication)
        .await
        .unwrap();
    let response = SoftToken::new(true)
        .unwrap()
        .0
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            {
                // SoftToken is a legacy non-resident fixture.
                let mut options = options.public_key;
                options
                    .authenticator_selection
                    .as_mut()
                    .unwrap()
                    .require_resident_key = false;
                options
            },
            300_000,
        )
        .unwrap();

    clock.set(first.enrolment.expires_at().unwrap());
    assert!(
        m.finish_additional_registration(&first.authentication, state, response.into())
            .await
            .is_err()
    );
    assert!(
        m.begin_additional_registration(&first.authentication)
            .await
            .is_err()
    );
}
