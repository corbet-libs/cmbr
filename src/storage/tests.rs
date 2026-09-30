use super::*;

async fn contract(store: impl Storage) {
    let idle = store.load().await.unwrap();
    assert!(!idle.is_busy());
    let busy = idle.next(Some(Operation::Busy)).unwrap();
    store.compare_exchange(&idle, &busy).await.unwrap();
    assert_eq!(store.compare_exchange(&idle, &busy).await, Err(Error::Busy));
    assert!(store.load().await.unwrap().is_busy());
    let clear = busy.next(None).unwrap();
    store.compare_exchange(&busy, &clear).await.unwrap();
    assert!(!store.load().await.unwrap().is_busy());
    assert_eq!(store.compare_exchange(&idle, &busy).await, Err(Error::Busy));
}

#[tokio::test]
async fn memory_cas() {
    contract(MemoryStorage::new("test").unwrap()).await;
}

#[tokio::test]
async fn libsql_cas_isolation_reopen_and_plans() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("coordinator.db").display());
    let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    let history = [crlt::Migration::new(1, "cmbr", SCHEMA)];
    db.migrate(&history).await.unwrap();
    contract(LibsqlStorage::new(&db, "test").unwrap()).await;
    let a = LibsqlStorage::new(&db, "test").unwrap();
    let b = LibsqlStorage::new(&db, "other").unwrap();
    let before = a.load().await.unwrap();
    let next = before.next(Some(Operation::Busy)).unwrap();
    a.compare_exchange(&before, &next).await.unwrap();
    assert!(!b.load().await.unwrap().is_busy());
    let reopened = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    reopened.migrate(&history).await.unwrap();
    assert!(
        LibsqlStorage::new(&reopened, "test")
            .unwrap()
            .load()
            .await
            .unwrap()
            .is_busy()
    );
    let scope = db.community("test").unwrap();
    scope
        .explain(LOAD, ())
        .await
        .unwrap()
        .assert_indexed()
        .unwrap();
    for sql in [INSERT, UPDATE] {
        scope
            .explain(sql, ["{}"])
            .await
            .unwrap()
            .assert_indexed()
            .unwrap();
    }
}

#[tokio::test]
async fn concurrent_acquisition_has_one_winner() {
    let storage = MemoryStorage::new("test").unwrap();
    let original = storage.load().await.unwrap();
    let next = original.next(Some(Operation::Busy)).unwrap();
    let (a, b) = tokio::join!(
        storage.compare_exchange(&original, &next),
        storage.compare_exchange(&original, &next)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
}
