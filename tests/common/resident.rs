//! Resident software authenticator fixture; production crypto remains upstream.
#![allow(dead_code)]
use passkey::{
    authenticator::{Authenticator, UserCheck, UserValidationMethod, extensions::HmacSecretConfig},
    client::{Client, DefaultClientData},
    types::{
        Passkey,
        ctap2::{Aaguid, Ctap2Error},
    },
};
use serde_json::{Value, json};

struct User;
#[async_trait::async_trait]
impl UserValidationMethod for User {
    type PasskeyItem = Passkey;
    async fn check_user<'a>(
        &self,
        _: Option<&'a Passkey>,
        _: bool,
        _: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: true,
        })
    }
    fn is_presence_enabled(&self) -> bool {
        true
    }
    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

#[derive(Clone, Default)]
pub struct Resident {
    credential: Option<Passkey>,
}
impl Resident {
    pub async fn ceremony(&mut self, mut options: Value, create: bool, origin: &str) -> Value {
        let original = options.clone();
        options["publicKey"]["extensions"]["prf"] = json!({"eval":{"first":"dGVzdC1vbmx5"}});
        let mut preserved = options.clone();
        preserved["publicKey"]["extensions"]
            .as_object_mut()
            .unwrap()
            .remove("prf");
        assert_eq!(preserved, original);
        let mut authenticator =
            Authenticator::new(Aaguid::new_empty(), self.credential.take(), User)
                .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        authenticator.set_make_credentials_with_signature_counter(true);
        let mut client = Client::new(authenticator);
        let origin = cpky::Url::parse(origin).unwrap();
        let response = if create {
            serde_json::to_value(
                client
                    .register(
                        &origin,
                        serde_json::from_value(options).unwrap(),
                        DefaultClientData,
                    )
                    .await
                    .unwrap(),
            )
            .unwrap()
        } else {
            serde_json::to_value(
                client
                    .authenticate(
                        &origin,
                        serde_json::from_value(options).unwrap(),
                        DefaultClientData,
                    )
                    .await
                    .unwrap(),
            )
            .unwrap()
        };
        self.credential = client.authenticator().store().clone();
        response
    }
}

pub fn strip_prf(response: &mut Value) -> Value {
    response["clientExtensionResults"]
        .as_object_mut()
        .unwrap()
        .remove("prf")
        .unwrap()
}
