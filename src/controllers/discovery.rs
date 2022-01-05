use rocket::{serde::json::Json, State};
use serde::Serialize;
use url::Url;

use crate::Mountpoint;
use crate::{guards::headers::RequestHost, ProviderConfiguration};

#[derive(Serialize, Debug)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String,
}

impl Default for OidcConfiguration {
    fn default() -> Self {
        Self {
            issuer: Default::default(),
            authorization_endpoint: Default::default(),
            token_endpoint: Default::default(),
            userinfo_endpoint: Default::default(),
            end_session_endpoint: Default::default(),
            jwks_uri: Default::default(),
        }
    }
}

impl OidcConfiguration {
    pub fn new(mountpoint: &str, issuer: &str) -> Result<Self, anyhow::Error> {
        let issuer = Url::parse(issuer)?;
        let base = issuer.join(&match mountpoint.ends_with("/") {
            true => format!("{}", mountpoint),
            false => format!("{}/", mountpoint),
        })?;

        Ok(Self {
            issuer: issuer.to_string(),
            authorization_endpoint: base.join("authorize")?.to_string(),
            token_endpoint: base.join("token")?.to_string(),
            userinfo_endpoint: base.join("userinfo")?.to_string(),
            end_session_endpoint: base.join("end_session")?.to_string(),
            jwks_uri: base.join("jwks")?.to_string(),
        })
    }
}

#[get("/.well-known/openid-configuration")]
pub fn get_discovery(
    config: &State<ProviderConfiguration>,
    req: RequestHost,
) -> Result<Json<OidcConfiguration>, String> {
    let mountpoint = config.mountpoint.get_path();

    Ok(Json(
        OidcConfiguration::new(&mountpoint, &format!("{}://{}", req.scheme, req.host))
            .map_err(|err| format!("could not build discovery document: {:?}", err))?,
    ))
}
