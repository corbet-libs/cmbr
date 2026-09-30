//! Real cmbr storage followed by cgrd's signed v2 opening verification.
mod common;
use common::*;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn stored_pin_opens_only_as_v2_in_its_authenticated_context() {
    let (_dir, db) = temporary().await;
    let facade = facade(&db, "garden", Clock::new());
    let (_, login) = pending(&facade, "garden").await;
    let salt = cpns::Salt::from_bytes(vec![33; 32]).unwrap();
    let context = cpns::FingerprintContext {
        community: "garden",
        member: SUBJECT,
        field: "age",
    };
    let value = cgrd::pin_value_bytes(&json!(34));
    let submission = cmbr::PinV2::seal(&context, &value, &salt);
    for (key, wrong) in [
        ("version", json!(1)),
        ("community", json!("elsewhere")),
        ("member", json!("someone")),
        ("field", json!("other")),
    ] {
        let mut wire = serde_json::to_value(&submission).unwrap();
        wire[key] = wrong;
        let invalid = serde_json::from_value(wire).unwrap();
        assert_eq!(
            facade.pin(&login.authentication, "age", &invalid).await,
            Err(cmbr::Error::Pin)
        );
        assert!(
            facade
                .get_pin(&login.authentication, "age")
                .await
                .unwrap()
                .is_none()
        );
    }
    let pin = facade
        .pin(&login.authentication, "age", &submission)
        .await
        .unwrap();
    let device = SigningKey::from_bytes(&[39; 32]);
    let issued = now() as u64 / 86_400 * 86_400;
    let until = issued + 86_400;
    let mut signer = cplc::csgn::PersistentSigner::create(
        cplc::csgn::MemoryStore::default(),
        "garden",
        cplc::csgn::SecretKey::from_seed(&mut [37; 32]),
        issued,
        30 * 86_400,
    )
    .await
    .unwrap();
    let settings = json!({"community":"garden","revision":1,"policy_epoch":1,"content":{"required_gates":[],"revoked_members":[],"revoked_devices":[],"reserved_handles":[]}});
    let schema = json!({"community":"garden","revision":1,"policy_epoch":1,"content":{"community":"garden","version":1,"public":[{"id":"age","label":"Age","kind":{"type":"integer","min":18,"max":120},"required":true,"filterable":true,"change_preset":"stable","no_contact_details":false}],"private":[]}});
    let settings = signer
        .sign(
            cplc::csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&settings).unwrap(),
            issued,
            until,
        )
        .await
        .unwrap();
    let schema = signer
        .sign(
            cplc::csgn::Kind::SchemaSnapshot,
            &serde_json::to_vec(&schema).unwrap(),
            issued,
            until,
        )
        .await
        .unwrap();
    for (digest, allowed) in [
        (*pin.fingerprint.as_bytes(), true),
        (*cpns::fingerprint(&value, &salt).as_bytes(), false),
        (
            *cpns::fingerprint_v2(
                &cpns::FingerprintContext {
                    community: "other",
                    ..context
                },
                &value,
                &salt,
            )
            .as_bytes(),
            false,
        ),
    ] {
        let credential = cgrd::Credential {
            community: "garden".into(),
            member: SUBJECT.into(),
            handle: HANDLE.into(),
            schema_version: 1,
            policy_epoch: 1,
            gates: vec![],
            pins: vec![cgrd::Pin {
                field: "age".into(),
                fingerprint: digest,
            }],
            devices: vec![device.verifying_key().to_bytes()],
        };
        let credential = signer
            .sign(
                cplc::csgn::Kind::Credential,
                &serde_json::to_vec(&credential).unwrap(),
                issued,
                until,
            )
            .await
            .unwrap();
        let body = json!({"community":"garden","member":SUBJECT,"device":device.verifying_key().to_bytes(),"credential":credential,"profile":{"scope":"public","profile":{"community":"garden","schema_version":1,"public":{"age":34}}},"openings":[{"field":"age","salt":salt.as_bytes()}]});
        let payload = serde_json::to_vec(&body).unwrap();
        let bundle = cgrd::Bundle {
            signature: device
                .sign(&cgrd::binding_bytes(&payload))
                .to_bytes()
                .to_vec(),
            payload,
        };
        let policy = cgrd::Policy {
            community: "garden",
            keys: signer.key_ring().unwrap(),
            now: now() as u64,
            minimum_epoch: 1,
            minimum_settings_revision: 1,
            minimum_schema_revision: 1,
            maximum_snapshot_age: 86_400,
            settings: &settings,
        };
        assert_eq!(
            cgrd::check(&bundle, &policy, &schema).is_admitted(),
            allowed
        );
    }
}
