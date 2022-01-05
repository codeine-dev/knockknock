use std::collections::HashMap;

use rocket::{serde::json::Json, State};
use serde::Serialize;

use crate::{prelude::Jwk, ProviderConfiguration};

#[derive(Serialize, Debug)]
pub struct Jwks {
    pub keys: Vec<serde_json::Map<String, serde_json::Value>>,
}

impl Default for Jwks {
    fn default() -> Self {
        Self {
            keys: Default::default(),
        }
    }
}

impl Jwks {
    pub fn with_key(key: Jwk) -> Self {
        let map: serde_json::Map<String, serde_json::Value> = key.0.into();
        let keys = vec![map];
        Self { keys }
    }
}

#[get("/jwks")]
pub fn get_jwks(config: &State<ProviderConfiguration>) -> Json<Jwks> {
    if let Some(key) = config.jwt.get_key() {
        return Json(Jwks::with_key(key));
    }

    Json(Jwks::default())
}
