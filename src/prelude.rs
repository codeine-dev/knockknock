use rocket::{form::Form, Build, Rocket};
use std::collections::HashMap;

use crate::{assets, controllers};

pub use super::{
    controllers::account::UsernamePasswordForm, 
    controllers::authorization::ClientAuthBundle,
    guards::headers::RequestHost, 
    jwt::*, 
    oidc::*, 
    types::*, 
    traits::oidc_adaptor::{AdaptorResult, OidcAdaptorImpl}, 
    ProviderConfiguration, 
    ProviderResult, 
};

// some types which get re-used a lot
pub type GenericForm = Form<HashMap<String, String>>;

// the main implementation type
pub type OidcAdaptor = Box<dyn OidcAdaptorImpl + Send + Sync>;

pub struct OidcConfiguration {
    pub mountpoint: Option<String>,
}

pub trait KnockKnock {
    fn enable_oidc(self, config: ProviderConfiguration) -> Self;
}

impl KnockKnock for Rocket<Build> {
    fn enable_oidc(self, config: ProviderConfiguration) -> Self {
        let base = config.mountpoint.get_path();

        self.manage(config)
            .mount(
                &base,
                routes![
                    controllers::authorization::authorize,
                    controllers::token::token,
                    controllers::introspect::introspect,
                    controllers::account::sign_in_post,
                    controllers::jwks::get_jwks,
                    assets::assets
                ],
            )
            .mount("/", routes![controllers::discovery::get_discovery])
    }
}
