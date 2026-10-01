use super::*;

async fn contract(store: impl Storage) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .to_bytes();
    store.set_device_keys("a", b"one", &[key]).await.unwrap();
    store.set_device_keys("a", b"two", &[key]).await.unwrap();
    assert_eq!(store.device_keys("a").await.unwrap().len(), 2);
    assert!(store.device_keys("b").await.unwrap().is_empty());
    for (id, keys) in [
        (b"".as_slice(), vec![key]),
        (b"one".as_slice(), vec![key, key]),
        (b"one".as_slice(), vec![[0; 32]]),
    ] {
        assert!(store.set_device_keys("a", id, &keys).await.is_err());
    }
    assert_eq!(store.device_keys("a").await.unwrap().len(), 2);
    store.set_device_keys("a", b"one", &[]).await.unwrap();
    let remaining = store.device_keys("a").await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].credential, b"two");
    assert_eq!(remaining[0].key, key);
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
    let history = [
        crlt::Migration::new(1, "cmbr", SCHEMA),
        crlt::Migration::new(2, "cmbr-device-keys", DEVICE_KEYS_SCHEMA),
    ];
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
    let a = ckyh::Uuid::from_u128(1);
    let b = ckyh::Uuid::from_u128(2);
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

async fn boundary_contract(store: impl Storage) {
    let keys: Vec<_> = (0u8..65)
        .map(|seed| ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes())
        .collect();
    for subject in ["".to_owned(), "\n".into(), "x".repeat(1025)] {
        assert!(store.set_device_keys(&subject, b"one", &keys[..1]).await.is_err());
        assert!(store.device_keys(&subject).await.is_err());
        assert!(store.probation(&subject).await.is_err());
        assert!(store.initialize_probation(&subject, 86400).await.is_err());
        assert!(store.clear_passed_probation(&subject, 86400).await.is_err());
        assert!(store.signal_revocation(&subject).await.is_err());
        assert!(store.revocation_pending(&subject).await.is_err());
        assert!(store.acknowledge(&Revocation { member: subject, generation: 1 }).await.is_err());
    }
    assert!(store.set_device_keys("bounded", &[1; 1025], &keys[..1]).await.is_err());
    assert!(store.set_device_keys("bounded", b"one", &keys).await.is_err());
    assert!(store.initialize_probation("bounded", u64::MAX).await.is_err());
    for count in [0, 1001] {
        assert!(store.revocations(count).await.is_err());
        assert!(store.prune_probation(86400, count).await.is_err());
    }
    assert!(!store.revocation_pending("absent").await.unwrap());
    store.clear_passed_probation("absent", 86400).await.unwrap();
    store.initialize_probation("bounded", 86400).await.unwrap();
    store.clear_passed_probation("bounded", 86400).await.unwrap();
    store.clear_passed_probation("bounded", 86401).await.unwrap();
    assert_eq!(store.probation("bounded").await.unwrap(), Some(None));
    store.signal_revocation("bounded").await.unwrap();
    assert!(store.revocation_pending("bounded").await.unwrap());
    let event = store.revocations(1000).await.unwrap().into_iter().find(|e| e.member == "bounded").unwrap();
    store.acknowledge(&event).await.unwrap();
    assert!(!store.revocation_pending("bounded").await.unwrap());
    // The store's contract cap is 1024 bindings, independently of facade policy.
    // Both actual adapters reject a corrupt/oversized retained set instead of truncating it.
    for credential in 0u8..17 {
        store.set_device_keys("bounded", &[credential], &keys[..64]).await.unwrap();
    }
    assert!(matches!(store.device_keys("bounded").await, Err(Error::Unavailable)));
    store.set_device_keys("bounded", &[16], &[]).await.unwrap();
    assert_eq!(store.device_keys("bounded").await.unwrap().len(), 1024);
}

#[tokio::test]
async fn memory_boundaries_and_generation_overflow_preserve_outbox() {
    assert!(MemoryStorage::new("").is_err());
    let store = MemoryStorage::new("memory-boundaries").unwrap();
    boundary_contract(store.clone()).await;
    store.state.lock().await.revocations.insert("overflow".into(), (i64::MAX as u64, false));
    assert_eq!(store.signal_revocation("overflow").await, Err(Error::Unavailable));
    assert!(!store.revocation_pending("overflow").await.unwrap());
    assert_eq!(format!("{:?}", Revocation { member: "private-subject".into(), generation: 7 }), "Revocation { .. }");
}

#[tokio::test]
async fn libsql_rejects_real_dynamic_type_corruption_and_keeps_atomic_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("boundaries.db").display());
    let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    db.migrate(&[
        crlt::Migration::new(1, "cmbr", SCHEMA),
        crlt::Migration::new(2, "cmbr-device-keys", DEVICE_KEYS_SCHEMA),
    ]).await.unwrap();
    assert!(LibsqlStorage::new(&db, "").is_err());
    let store = LibsqlStorage::new(&db, "sql-boundaries").unwrap();
    boundary_contract(store.clone()).await;
    assert!(store.clear_passed_probation("bounded", u64::MAX).await.is_err());
    assert!(store.prune_probation(u64::MAX, 1).await.is_err());
    assert!(store.acknowledge(&Revocation { member: "bounded".into(), generation: u64::MAX }).await.is_err());
    let key = ed25519_dalek::SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes();
    store.set_device_keys("corrupt", b"one", &[key]).await.unwrap();
    store.scope.execute("UPDATE cmbr_device_keys SET credential = ?1 WHERE subject = ?2", params!["text", "corrupt"]).await.unwrap();
    assert!(matches!(store.device_keys("corrupt").await, Err(Error::Unavailable)));
    store.scope.execute("UPDATE cmbr_device_keys SET credential = ?1, signing_key = ?2 WHERE subject = ?3", params![b"one".as_slice(), "x".repeat(32), "corrupt"]).await.unwrap();
    assert!(matches!(store.device_keys("corrupt").await, Err(Error::Unavailable)));
    store.scope.execute("UPDATE cmbr_device_keys SET signing_key = ?1 WHERE subject = ?2", params![[0u8; 32].as_slice(), "corrupt"]).await.unwrap();
    assert!(matches!(store.device_keys("corrupt").await, Err(Error::Unavailable)));
    store.signal_revocation("overflow").await.unwrap();
    store.scope.execute("UPDATE cmbr_revocations SET generation = ?1, pending = 0 WHERE subject = ?2", params![i64::MAX, "overflow"]).await.unwrap();
    assert_eq!(store.signal_revocation("overflow").await, Err(Error::Unavailable));
    assert!(!store.revocation_pending("overflow").await.unwrap());
    store.scope.execute("UPDATE cmbr_revocations SET generation = ?1, pending = 1 WHERE subject = ?2", params!["corrupt", "overflow"]).await.unwrap();
    assert!(matches!(store.revocations(1000).await, Err(Error::Unavailable)));
    store.scope.execute("UPDATE cmbr_probation SET probation_until = ?1 WHERE subject = ?2", params!["corrupt", "bounded"]).await.unwrap();
    assert_eq!(store.probation("bounded").await, Err(Error::Unavailable));
}
