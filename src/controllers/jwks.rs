use jsonwebtoken::jwk::JwkSet;
use rocket::{serde::json::Json, State};
use serde::Serialize;

use crate::{ProviderConfiguration};

// #[derive(Serialize, Debug)]
// pub struct Jwks {
//     pub keys: Vec<serde_json::Map<String, serde_json::Value>>,
// }

// impl Default for Jwks {
//     fn default() -> Self {
//         Self {
//             keys: Default::default(),
//         }
//     }
// }

// impl Jwks {
//     pub fn with_key(key: Jwk) -> Self {
//         let map: serde_json::Map<String, serde_json::Value> = key.0.into();
//         let keys = vec![map];
//         Self { keys }
//     }
// }

#[get("/jwks")]
pub fn get_jwks(config: &State<ProviderConfiguration>) -> Json<JwkSet> {
    if let Some(key) = config.jwt.get_public_key() {
        return Json(JwkSet { keys: vec![] });
    }

    Json(JwkSet { keys: vec![] })
}
