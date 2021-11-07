use hmac::{Hmac, NewMac};
use jwt::{SignWithKey, VerifyWithKey};
use sha2::Sha256;

pub type JwtBuilder = Box<dyn JwtSign + Send + Sync>;

pub struct JwtSharedSecret {
    key: Hmac<Sha256>,
}

impl JwtSharedSecret {
    pub fn with_secret(secret: &str) -> JwtBuilder {
        Box::new(JwtSharedSecret {
            key: Hmac::new_from_slice(secret.as_bytes()).unwrap(),
        })
    }
}

pub trait JwtSign {
    fn sign(&self, claims: serde_json::Value) -> String;
    fn decode(&self, token: &str) -> Result<serde_json::Value, ()>;
}

impl JwtSign for JwtSharedSecret {
    fn sign(&self, claims: serde_json::Value) -> String {
        claims
            .sign_with_key(&self.key)
            .expect("Error signing claims")
    }

    fn decode(&self, token: &str) -> Result<serde_json::Value, ()> {
        token.verify_with_key(&self.key).map_err(|_| ())
    }
}
