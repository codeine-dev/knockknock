use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use libknockknock::{prelude::*, AuthError, UsernamePasswordForm};

#[derive(Default)]
struct InMemoryStateStore {
    store: Arc<Mutex<HashMap<String, String>>>,
}

#[async_trait]
impl StateStore for InMemoryStateStore {
    fn build(&self) -> IStateStore {
        Box::new(InMemoryStateStore::default())
    }

    async fn get_state(&self, key: &str) -> StateStoreResult<String> {
        self.store
            .lock()
            .unwrap()
            .get(key)
            .ok_or(StateStoreError::KeyNotFound {
                key: key.to_owned(),
            })
            .map(|v| v.to_owned())
    }

    async fn set_state(&self, value: &str) -> StateStoreResult<String> {
        let key = uuid::Uuid::new_v4();
        let key = key
            .to_simple()
            .encode_lower(&mut uuid::Uuid::encode_buffer())
            .to_owned();

        self.store
            .lock()
            .unwrap()
            .insert(key.clone(), value.to_owned());

        Ok(key)
    }
}

struct MyProviders {}

#[async_trait]
impl Providers for MyProviders {
    async fn issue_grant(
        &self,
        sub: &str,
        _scopes: &[&str],
        _response_types: &[ResponseType],
    ) -> ProviderResult<Grant> {
        let builder = GrantBuilder::for_subject(sub);

        // all grants provide the Admin claim
        builder.with_claim("Admin", "").build()
    }

    async fn validate_login(&self, login: UsernamePasswordForm) -> ProviderResult<String> {
        // only the admin is OK
        if login.username != "admin" || login.password != "password" {
            return Err(());
        }

        Ok("admin-sub".to_owned())
    }

    async fn validate_client(&self, client_id: &str, client_secret: &str) -> ProviderResult<()> {
        if client_id != "user" || client_secret != "pass" {
            return Err(());
        }

        // all clients are OK
        Ok(())
    }

    async fn validate_authorization(
        &self,
        _client_id: &str,
        _response_type: &[libknockknock::oidc::ResponseType],
        _scope: &[&str],
        _redirect_url: &str,
        _state: Option<&str>,
    ) -> Result<(), String> {
        // all clients are OK
        Ok(())
    }

    async fn store_grant(&self, grant: &Grant, code: &str) -> ProviderResult<()> {
        println!("Grant: {:?}", grant);
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let config = Configuration {
        providers: Box::new(MyProviders {}),
        jwt_builder: JwtSharedSecret::with_secret("secret"),
        state_store: InMemoryStateStore::default().build(),
    };

    if let Err(_) = start(config).await {
        println!("An error occurred during startup :(");
    }
}
