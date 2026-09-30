use super::*;

async fn contract(store: impl Storage) {
    assert_eq!(store.probation("a").await.unwrap(), None);
    store.initialize_probation("a", 14 * 86400).await.unwrap();
    store.initialize_probation("a", 30 * 86400).await.unwrap();
    assert_eq!(store.probation("a").await.unwrap(), Some(Some(14 * 86400)));
    store
        .clear_passed_probation("a", 14 * 86400 - 1)
        .await
        .unwrap();
    assert_eq!(store.probation("a").await.unwrap(), Some(Some(14 * 86400)));
    store.prune_probation(14 * 86400, 10).await.unwrap();
    store.initialize_probation("a", 30 * 86400).await.unwrap();
    assert_eq!(store.probation("a").await.unwrap(), Some(None));
    assert_eq!(store.probation("b").await.unwrap(), None);
    assert!(store.initialize_probation("b", 86401).await.is_err());
    store.signal_revocation("a").await.unwrap();
    let first = store.revocations(1).await.unwrap().remove(0);
    store.signal_revocation("a").await.unwrap();
    store.acknowledge(&first).await.unwrap();
    let second = store.revocations(1).await.unwrap().remove(0);
    assert!(second.generation > first.generation);
    store.acknowledge(&second).await.unwrap();
    assert!(store.revocations(1).await.unwrap().is_empty());
    store.signal_revocation("a").await.unwrap();
    store.acknowledge(&first).await.unwrap();
    store.acknowledge(&second).await.unwrap();
    assert_eq!(store.revocations(1).await.unwrap().len(), 1);
}
#[tokio::test]
async fn memory_probation_and_revocation_contract() {
    contract(MemoryStorage::new("test").unwrap()).await;
}
#[tokio::test]
async fn libsql_coarse_facts_are_indexed_isolated_and_persistent() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("facts.db").display());
    let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    let history = [crlt::Migration::new(1, "cmbr", SCHEMA)];
    db.migrate(&history).await.unwrap();
    contract(LibsqlStorage::new(&db, "test").unwrap()).await;
    assert_eq!(
        LibsqlStorage::new(&db, "other")
            .unwrap()
            .probation("a")
            .await
            .unwrap(),
        None
    );
    let reopened = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    reopened.migrate(&history).await.unwrap();
    let store = LibsqlStorage::new(&reopened, "test").unwrap();
    assert_eq!(store.probation("a").await.unwrap(), Some(None));
    assert_eq!(store.revocations(10).await.unwrap().len(), 1);
    // Every query above is also checked by crlt's runtime index-plan enforcement.
}
#[tokio::test]
async fn cancellation_and_errors_drop_only_the_affected_member_guard() {
    let a = cpky::Uuid::from_u128(1);
    let b = cpky::Uuid::from_u128(2);
    let guard = member_lock("locks", a).await;
    let other = tokio::time::timeout(std::time::Duration::from_secs(1), member_lock("locks", b))
        .await
        .unwrap();
    drop(other);
    let task = tokio::spawn(async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    });
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let _again = tokio::time::timeout(std::time::Duration::from_secs(1), member_lock("locks", a))
        .await
        .unwrap();
}
