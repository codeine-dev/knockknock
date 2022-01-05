use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use libknockknock::prelude::*;

use log::{debug, info};
use rocket::{get, launch, routes, State};

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
    async fn claims_for_scope(&self, scope: &str) -> Vec<String> {
        debug!("Claims for scope: {}", scope);
        match scope {
            "email" => vec!["email"].iter().map(|&s| String::from(s)).collect(),
            "roles" => vec!["Admin"].iter().map(|&s| String::from(s)).collect(),
            _ => vec![],
        }
    }

    async fn scopes_for_resource(&self, resource: &str) -> Vec<String> {
        debug!("Scopes for resource: {}", resource);
        match resource {
            "any" => vec!["email"].iter().map(|&s| String::from(s)).collect(),
            _ => vec![],
        }
    }

    async fn issue_grant(
        &self,
        sub: &str,
        scopes: &[&str],
        response_type: ResponseType,
        request: &RequestHost,
        bundle: &ClientAuthBundle,
    ) -> ProviderResult<Grant> {
        debug!("Issue grant for sub: {}", sub);
        let builder = GrantBuilder::for_subject(sub);

        // all grants provide the Admin claim
        let grant = builder
            .with_claim("Admin", "")
            .with_claim("email", "richbayliss@gmail.com")
            .with_scope(&scopes.join(" "))
            .expires_in_secs(10);

        match response_type {
            ResponseType::IdToken => {
                let client_id = bundle.client_id.to_owned();
                let issuer = format!("{}://{}", request.scheme, request.host);
                grant.build_id_token(&client_id, &issuer)
            }
            _ => grant.build(),
        }
    }

    async fn validate_login(&self, login: UsernamePasswordForm) -> ProviderResult<String> {
        debug!("Validate login: {:?}", login);
        // only the admin is OK
        if login.username != "admin" || login.password != "password" {
            return Err(());
        }

        Ok("admin-sub".to_owned())
    }

    async fn validate_client(&self, client_id: &str, client_secret: &str) -> ProviderResult<()> {
        debug!("Validate client: {} ({})", client_id, client_secret);
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

#[get("/")]
async fn get_index(test: &State<String>) -> String {
    format!("Hello, {}", test)
}

#[launch]
fn rocket() -> _ {
    setup_logger(log::LevelFilter::Debug).expect("Could not configure the logger");

    let jwt = RsaJwtFactory::from_private_pem(include_str!("rsa_private.pem"))
        .expect("Couldn't build JWT factory");

    let mountpoint = Mountpoint::default();

    let config = ProviderConfiguration {
        mountpoint,
        adaptor: Box::new(InMemoryAdaptor::default()),
        jwt: Box::new(jwt),
    };

    let test = String::from("World");

    rocket::build()
        .enable_oidc(config)
        .manage(test)
        .mount("/", routes![get_index])
}
