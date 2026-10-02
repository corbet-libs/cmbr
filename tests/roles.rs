//! Real passkeys, membership lifecycle and SQL register role authorization.
//! Seeding the original register establishes pre-existing roles only; root
//! voucher bootstrap is a separate integration requirement.
mod common;
use cmbr::{Error, Role, Uuid};
use common::*;
use std::time::Duration;

async fn admitted(m: &Facade, number: u128) -> cmbr::Authentication {
    let user = Uuid::from_u128(number);
    let subject = format!("{number:096x}");
    let mut device = register(m, user, &subject).await;
    let auth = login(m, &mut device, user).await.authentication;
    m.reserve_handle(&auth, &format!("member_{number}"), &[])
        .await
        .unwrap();
    m.admit_test(
        &auth,
        &policy("roles"),
        &[test_gate("roles", &subject)],
        lease(),
    )
    .await
    .unwrap();
    auth
}

async fn seed_role(db: &crlt::Db, m: &Facade, auth: &cmbr::Authentication, role: Role) {
    let row = m.resume(auth).await.unwrap();
    crgs::Register::new(
        crgs::LibsqlStorage::new(db.community("roles").unwrap()),
        crgs::ReleasePeriod::default(),
    )
    .set_role(&row.member_id(), role)
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_and_root_rights_use_one_current_persistent_role() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "roles", Clock::new());
    let root = admitted(&m, 1).await;
    let admin = admitted(&m, 2).await;
    let member = admitted(&m, 3).await;
    seed_role(&db, &m, &root, Role::Root).await;
    assert_eq!(m.role(&member).await.unwrap().role(), Role::Member);
    assert_eq!(
        m.set_role(&member, member.member(), Role::Root).await,
        Err(Error::Policy)
    );
    m.set_role(&root, admin.member(), Role::Admin)
        .await
        .unwrap();
    m.set_role(&admin, member.member(), Role::Admin)
        .await
        .unwrap();
    assert_eq!(m.role(&member).await.unwrap().role(), Role::Admin);
    assert_eq!(
        m.set_role(&admin, member.member(), Role::Root).await,
        Err(Error::Policy)
    );
    assert_eq!(
        m.set_role(&admin, root.member(), Role::Admin).await,
        Err(Error::Policy)
    );
    m.set_role(&admin, member.member(), Role::Member)
        .await
        .unwrap();
    m.set_role(&root, member.member(), Role::Root)
        .await
        .unwrap();
    m.set_role(&member, root.member(), Role::Member)
        .await
        .unwrap();
    let reopened = facade(&db, "roles", Clock::new());
    assert_eq!(reopened.role(&root).await.unwrap().role(), Role::Member);
    assert_eq!(reopened.role(&member).await.unwrap().role(), Role::Root);
    // Self-demotion acquires the same member queue only once.
    tokio::time::timeout(
        Duration::from_secs(10),
        reopened.set_role(&member, member.member(), Role::Member),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        reopened
            .set_role(&member, admin.member(), Role::Member)
            .await,
        Err(Error::Policy)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_garden_operation_holds_demotion_and_revocation_until_it_completes() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "roles", Clock::new());
    let root = admitted(&m, 1).await;
    let admin = admitted(&m, 2).await;
    seed_role(&db, &m, &root, Role::Root).await;
    m.set_role(&root, admin.member(), Role::Admin)
        .await
        .unwrap();
    let lease = m.role(&admin).await.unwrap();
    assert_eq!(
        lease.valid_until(),
        "2027-10-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            .timestamp() as u64
    );
    let writer = m.clone();
    let actor = root.clone();
    let target = admin.member();
    let mut demotion =
        tokio::spawn(async move { writer.set_role(&actor, target, Role::Member).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut demotion)
            .await
            .is_err()
    );
    drop(lease);
    tokio::time::timeout(Duration::from_secs(10), demotion)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(m.role(&admin).await.unwrap().role(), Role::Member);
    let lease = m.role(&root).await.unwrap();
    let writer = m.clone();
    let actor = root.clone();
    let credential = root.credential_id().clone();
    let mut revoke = tokio::spawn(async move { writer.revoke_passkey(&actor, credential).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut revoke)
            .await
            .is_err()
    );
    drop(lease);
    tokio::time::timeout(Duration::from_secs(10), revoke)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(m.role(&root).await.is_err());
    assert!(m.set_role(&root, admin.member(), Role::Root).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_lapsed_expired_and_foreign_members_have_no_garden_authority() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "roles", clock.clone());
    let root = admitted(&m, 1).await;
    seed_role(&db, &m, &root, Role::Root).await;
    let mut device = register(&m, Uuid::from_u128(2), &format!("{:096x}", 2)).await;
    let pending = login(&m, &mut device, Uuid::from_u128(2))
        .await
        .authentication;
    assert!(matches!(m.role(&pending).await, Err(Error::Transition)));
    assert_eq!(
        m.set_role(&root, pending.member(), Role::Admin).await,
        Err(Error::Transition)
    );
    let foreign = facade(&db, "foreign", Clock::new());
    assert!(foreign.role(&root).await.is_err());
    m.lapse_test(&root, &policy("roles"), &[]).await.unwrap();
    assert!(matches!(m.role(&root).await, Err(Error::Transition)));
    m.admit_test(
        &root,
        &policy("roles"),
        &[test_gate("roles", &format!("{:096x}", 1))],
        lease(),
    )
    .await
    .unwrap();
    clock.set(
        "2027-10-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            .timestamp(),
    );
    assert!(matches!(m.role(&root).await, Err(Error::Transition)));
    assert_eq!(
        m.set_role(&root, root.member(), Role::Member).await,
        Err(Error::Transition)
    );
}
