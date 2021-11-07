use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use libknockknock::{prelude::*, AuthRequest, SealedGrantResponses, UsernamePasswordForm};

use log::{debug, error};

struct InMemoryAdaptor {
    grants: Arc<Mutex<HashMap<String, String>>>,
}

impl Default for InMemoryAdaptor {
    fn default() -> Self {
        Self {
            grants: Arc::new(Mutex::new(HashMap::<String, String>::new())),
        }
    }
}

#[rocket::async_trait]
impl OidcAdaptorImpl for InMemoryAdaptor {
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
            .with_scope(&scopes.join(" "))
            .expires_in_secs(10);

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
        self.grants
            .lock()
            .unwrap()
            .insert(code.to_owned(), serde_json::to_string(grant).unwrap());

        Ok(())
    }

    async fn retrieve_grant(&self, code: &str) -> ProviderResult<SealedGrantResponses> {
        debug!("Retrieving grants for {}", code);
        let grants = self
            .grants
            .lock()
            .unwrap()
            .get(code)
            .map(|g| serde_json::from_str::<SealedGrantResponses>(&g).unwrap());

        match grants {
            Some(grants) => {
                debug!("Grants found for {}: {:?}", code, grants);
                Ok(grants)
            }
            None => Err(()),
        }
    }
}

pub fn setup_logger(level: log::LevelFilter) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                // record.target(),
                record.level(),
                message
            ))
        })
        .level(level)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[rocket::main]
async fn main() {
    setup_logger(log::LevelFilter::Debug).expect("Could not configure the logger");

    let config = ProviderConfiguration {
        adaptor: Box::new(InMemoryAdaptor::default()),
        jwt_builder: JwtSharedSecret::with_secret("secret"),
    };

    libknockknock::prelude::start(config)
        .await
        .map_err(|err| {
            error!("An error occurred during startup: {:?}", err);
        })
        .unwrap();
}
