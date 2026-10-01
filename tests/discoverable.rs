mod common;
use common::{
    resident::{Resident, strip_prf},
    *,
};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn restore_returns_the_existing_membership_and_rechecks_revocation_and_expiry() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let members = facade(&db, "a", clock.clone());
    let mut device = Resident::default();
    let (options, pending) = members.begin_registration(USER, SUBJECT).await.unwrap();
    let options = serde_json::to_value(options).unwrap();
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    let mut response = device.ceremony(options, true, ORIGIN).await;
    assert!(serde_json::from_value::<cpky::RegisterPublicKeyCredential>(response.clone()).is_err());
    let prf = strip_prf(&mut response);
    assert_eq!(prf["enabled"], true);
    let before = members
        .finish_registration(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    let reopened = facade(&db, "a", clock.clone());
    let mut phone = device.clone();
    let (options, pending) = reopened.begin_discoverable_login().await.unwrap();
    let options = serde_json::to_value(options).unwrap();
    assert_eq!(options["publicKey"]["allowCredentials"], json!([]));
    let mut response = phone.ceremony(options, false, ORIGIN).await;
    assert_eq!(strip_prf(&mut response)["results"], prf["results"]);
    let login = reopened
        .finish_login(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    assert_eq!(login.authentication.member(), USER);
    assert_eq!(login.enrolment, before);
    assert_eq!(
        reopened.resume(&login.authentication).await.unwrap(),
        before
    );

    let (options, pending) = reopened.begin_discoverable_login().await.unwrap();
    let mut response = phone
        .ceremony(serde_json::to_value(options).unwrap(), false, ORIGIN)
        .await;
    strip_prf(&mut response);
    reopened
        .revoke_passkey(
            &login.authentication,
            login.authentication.credential_id().clone(),
        )
        .await
        .unwrap();
    assert!(
        reopened
            .finish_login(pending, serde_json::from_value(response).unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        reopened.enrolment_state(USER).await.unwrap().state(),
        cnrl::State::Released
    );
    assert!(reopened.resume(&login.authentication).await.is_err());

    // A still-valid passkey cannot restore an expired membership.
    let other = facade(&db, "b", clock.clone());
    let (options, pending) = other.begin_registration(USER, SUBJECT).await.unwrap();
    let mut fresh = Resident::default();
    let mut response = fresh
        .ceremony(serde_json::to_value(options).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut response);
    other
        .finish_registration(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    let (options, pending) = other.begin_discoverable_login().await.unwrap();
    let mut response = fresh
        .ceremony(serde_json::to_value(options).unwrap(), false, ORIGIN)
        .await;
    strip_prf(&mut response);
    clock.set(now() + 4 * 86_400);
    assert!(
        other
            .finish_login(pending, serde_json::from_value(response).unwrap())
            .await
            .is_err()
    );
}
