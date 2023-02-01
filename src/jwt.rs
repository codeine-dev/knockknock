use jsonwebtoken::{Header, EncodingKey, encode, Algorithm, decode, DecodingKey, Validation, jwk::Jwk};
use rsa::{pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey}, RsaPrivateKey, RsaPublicKey};
use thiserror::Error;

use crate::{prelude::Grant};

pub type JwtFactory = Box<dyn JwtSign + Send + Sync>;

impl Clone for JwtFactory {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[derive(Error,Debug)]
pub enum JwtSignError {
    #[error("SigningError: {0}")]
    SigningError(String),
    #[error("Not valid yet")]
    NotBefore,
    #[error("Not valid anymore")]
    NotAfter,
    #[error("Not valid at all")]
    Invalid,
    #[error("Invalid: {0}")]
    InvalidBecause(String),
}

pub trait JwtSign {
    fn sign(&self, payload: &Grant) -> Result<String, JwtSignError>;
    fn verify(&self, token: &str) -> Result<Grant, JwtSignError>;
    fn get_public_key(&self) -> Option<&RsaPublicKey>;
    fn box_clone(&self) -> JwtFactory;
}

pub struct RsaJwtFactory {
    pem: String,
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl RsaJwtFactory {
    pub fn from_private_pem(pem: &str) -> Result<Self, anyhow::Error> {

        let private_key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        let public_key = private_key.to_public_key();

        let private_pem = private_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::default())?.to_string();
        let public_pem = public_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::default())?.to_string();

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|err| anyhow::format_err!("error loading Private PEM data: {:?}", err))?;

        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|err| anyhow::format_err!("error loading Public PEM data: {:?}", err))?;

        Ok(Self {
            public_key,
            private_key,
            encoding_key,
            decoding_key,
            pem: String::from(pem),
        })
    }
}

impl JwtSign for RsaJwtFactory {
    fn sign(&self, payload: &Grant) -> Result<String, JwtSignError> {
        debug!("Signer payload: {:?}", payload);
        
        encode(
            &Header::new(Algorithm::RS256), 
            payload, 
            &self.encoding_key,
        )
            .map_err(|_| JwtSignError::SigningError("Unable to sign payload".to_owned()))
    }

    fn verify(&self, token: &str) -> Result<Grant, JwtSignError> {
        let token = decode::<Grant>(
            &token,
            &self.decoding_key,
            &Validation::new(Algorithm::RS256),
        ).map_err(|reason| JwtSignError::InvalidBecause(reason.to_string()))?;

        Ok(token.claims)
    }

    fn get_public_key(&self) -> Option<&RsaPublicKey> {
        Some(&self.public_key)
    }

    fn box_clone(&self) -> JwtFactory {
        let clone = Self {
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            encoding_key: self.encoding_key.clone(),
            decoding_key: self.decoding_key.clone(),
            pem: self.pem.clone(),
        };

        Box::new(clone)
    }
}
