use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use libknockknock::{prelude::*, AuthRequest, SealedGrantResponses, UsernamePasswordForm};
use log::{debug, error};

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

    async fn set_state(&self, key: Option<&str>, value: &str) -> StateStoreResult<String> {
        let key = key
            .map(|k| k.to_owned())
            .or_else(|| {
                let key = uuid::Uuid::new_v4();
                let key = key
                    .to_simple()
                    .encode_lower(&mut uuid::Uuid::encode_buffer())
                    .to_owned();
                Some(key)
            })
            .unwrap();

        self.store
            .lock()
            .unwrap()
            .insert(key.clone(), value.to_owned());

        Ok(key)
    }
}

struct MyProviders {
    grant_store: Box<InMemoryStateStore>,
}

#[async_trait]
impl Providers for MyProviders {
    async fn issue_grant(
        &self,
        sub: &str,
        scopes: &[&str],
        response_type: ResponseType,
        request: &AuthRequest,
    ) -> ProviderResult<Grant> {
        let builder = GrantBuilder::for_subject(sub);

        // all grants provide the Admin claim
        let grant = builder
            .with_claim("Admin", "")
            .with_scope(&scopes.join(" "));

        match response_type {
            ResponseType::IdToken => {
                let client_id = request.client_id.as_ref();
                let client_id = client_id.expect("client_id is missing").to_owned();

                let issuer = request.host.to_owned();
                grant.build_id_token(&client_id, &issuer)
            }
            _ => grant.build(),
        }
    }

    async fn validate_login(&self, login: UsernamePasswordForm) -> ProviderResult<String> {
        // only the admin is OK
        if login.username != "admin" || login.password != "password" {
            return Err(());
        }

        Ok("admin-sub".to_owned())
    }

    async fn validate_client(&self, client_id: &str, client_secret: &str) -> ProviderResult<()> {
        if client_id != "any" || client_secret != "any" {
            return Err(());
        }

        // all clients are OK
        Ok(())
    }

    async fn validate_authorization(
        &self,
        _client_id: &str,
        _response_type: &[ResponseType],
        _scope: &[&str],
        _redirect_url: &str,
        _state: Option<&str>,
    ) -> Result<(), String> {
        // all clients are OK
        Ok(())
    }

    async fn store_grant(&self, grant: &SealedGrantResponses, code: &str) -> ProviderResult<()> {
        debug!("Storing grants for {}: {:?}", code, grant);
        self.grant_store
            .set_state(Some(code), &serde_json::to_string(grant).unwrap())
            .await
            .map_err(|_| {
                error!("Unable to store grant: {}", code);
                ()
            })?;
        Ok(())
    }

    async fn retrieve_grant(&self, code: &str) -> ProviderResult<SealedGrantResponses> {
        debug!("Retrieving grants for {}", code);
        let grants = self.grant_store.get_state(code).await.map_err(|_| {
            error!("Unable to get grant: {}", code);
            ()
        })?;

        let grants: SealedGrantResponses = serde_json::from_str(&grants).unwrap();
        debug!("Grants found for {}: {:?}", code, grants);
        Ok(grants)
    }
}

#[tokio::main]
async fn main() {
    let config = Configuration {
        providers: Box::new(MyProviders {
            grant_store: Box::new(InMemoryStateStore::default()),
        }),
        jwt_builder: JwtSharedSecret::with_secret("secret"),
        state_store: InMemoryStateStore::default().build(),
    };

    if let Err(_) = start(config).await {
        println!("An error occurred during startup :(");
    }
}
