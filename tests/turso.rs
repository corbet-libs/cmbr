//! Optional round trip against a caller-supplied disposable Turso database.
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn optional_real_turso() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("skip: TURSO_URL and TURSO_TOKEN are required");
        return;
    };
    if url.is_empty() || token.is_empty() {
        eprintln!("skip: both Turso values must be nonempty");
        return;
    }
    let db = common::open(&url, &token).await;
    let community = format!("cmbr-test-{}", cpky::Uuid::new_v4());
    let facade = common::facade(&db, &community, common::Clock::new());
    let mut device = common::register(&facade, common::USER, common::SUBJECT).await;
    let login = common::login(&facade, &mut device, common::USER).await;
    assert_eq!(
        facade.resume(&login.authentication).await.unwrap(),
        login.enrolment
    );
}
