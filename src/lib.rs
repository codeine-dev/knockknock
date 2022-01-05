#[macro_use]
pub extern crate rocket;
mod assets;
mod controllers;
mod guards;
mod jwt;
mod oidc;
pub mod prelude;
mod traits;

use std::ops::Deref;

use prelude::{Grant, JwtFactory, OidcAdaptor};
use rocket::serde::{Deserialize, Serialize};
use serde_json::json;

pub type ProviderResult<T> = std::result::Result<T, ()>;

#[derive(Serialize)]
pub enum LoginState {
    Challenge {
        factor: String,
        data: serde_json::Value,
    },
    Success {
        redirect: String,
    },
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct GrantResponses {
    pub access_token: Option<Grant>,
    pub id_token: Option<Grant>,
}

impl GrantResponses {
    pub fn to_sealed(&self, signer: &Box<dyn jwt::JwtSign + Sync + Send>) -> SealedGrantResponses {
        SealedGrantResponses {
            access_token: self.access_token.as_ref().map(|t| {
                debug!("Sealing grant: {:?}", t);
                signer.sign(json!(t))
            }),
            id_token: self.id_token.as_ref().map(|t| {
                debug!("Sealing grant: {:?}", t);
                signer.sign(json!(t))
            }),
        }
    }

    pub fn from_sealed(sealed: &SealedGrantResponses, factory: &JwtFactory) -> Result<Self, ()> {
        let access_token: Option<Grant> = sealed.access_token.as_ref().map(|sealed| {
            factory
                .decode(&sealed)
                .ok()
                .map(|v| serde_json::from_value(v).ok().unwrap())
                .unwrap()
        });

        let id_token: Option<Grant> = sealed.id_token.as_ref().map(|sealed| {
            factory
                .decode(&sealed)
                .ok()
                .map(|v| serde_json::from_value(v).ok().unwrap())
                .unwrap()
        });

        Ok(Self {
            access_token,
            id_token,
        })
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct SealedGrantResponses {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
}

pub struct Mountpoint(String);

impl Mountpoint {
    pub fn get_path(&self) -> String {
        self.0.clone()
    }
}

impl Default for Mountpoint {
    fn default() -> Self {
        Self("/connect".to_owned())
    }
}

pub struct ProviderConfiguration {
    pub mountpoint: Mountpoint,
    pub jwt: jwt::JwtFactory,
    pub adaptor: OidcAdaptor,
}
