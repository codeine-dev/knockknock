use rocket::form::Form;
use std::collections::HashMap;

pub use super::{
    controllers::account::UsernamePasswordForm, controllers::authorization::ClientAuthBundle,
    guards::headers::RequestHost, jwt::*, oidc::*, start, traits::oidc_adaptor::OidcAdaptorImpl,
    LoginState, ProviderConfiguration, ProviderResult, SealedGrantResponses,
};

// some types which get re-used a lot
pub type GenericForm = Form<HashMap<String, String>>;

// the main implementation type
pub type OidcAdaptor = Box<dyn OidcAdaptorImpl + Send + Sync>;
