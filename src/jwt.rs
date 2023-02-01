use thiserror::Error;
use josekit::{jwt::*, jwk::alg::rsa::RsaKeyPair, jws::{JwsHeader, alg::rsassa::RsassaJwsAlgorithm::Rs256}, jwt::JwtPayload};

#[derive(Clone, Debug)]
pub struct Jwk(pub josekit::jwk::Jwk);

impl Jwk {
    pub fn to_public_key(&self) -> Result<Self, anyhow::Error> {
        let public_key = self.0.to_public_key()?;
        Ok(Jwk(public_key))
    }
}

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
}

pub trait JwtSign {
    fn sign(&self, payload: &JwtPayload) -> Result<String, JwtSignError>;
    fn verify(&self, token: &str) -> Result<JwtPayload, JwtSignError>;
    fn get_public_key(&self) -> Option<Jwk>;
    fn box_clone(&self) -> JwtFactory;
}

pub struct RsaJwtFactory {
    pem: String,
    jwk: Jwk,
}

impl RsaJwtFactory {
    pub fn from_private_pem(pem: &str) -> Result<Self, anyhow::Error> {
        let keypair = RsaKeyPair::from_pem(pem)
            .map_err(|err| anyhow::format_err!("error loading PEM data: {:?}", err))?;

        let jwk = keypair.to_jwk_key_pair();

        Ok(Self {
            jwk: Jwk(jwk),
            pem: String::from(pem),
        })
    }
}

impl JwtSign for RsaJwtFactory {
    fn sign(&self, payload: &JwtPayload) -> Result<String, JwtSignError> {
        debug!("Signer payload: {:?}", payload);
        
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
    
        // create the signed JWT...
        let signer = 
            Rs256.signer_from_jwk(&self.jwk.0)
                .map_err(|_| JwtSignError::SigningError("Unable to build signer from JWK".to_owned()))?;
        
        encode_with_signer(&payload, &header, &signer)
            .map_err(|_| JwtSignError::SigningError("Unable to sign payload".to_owned()))
    }

    fn verify(&self, token: &str) -> Result<JwtPayload, JwtSignError> {
        if let Ok(public_key) = &self.jwk.to_public_key() {
            let verifier = 
                Rs256.verifier_from_jwk(&public_key.0)
                    .map_err(|_| JwtSignError::SigningError("Unable to build verifier from public key".to_owned()))?;

            let (payload, _header) = 
                decode_with_verifier(&token, &verifier)
                    .map_err(|_| JwtSignError::SigningError("Unable to verify".to_owned()))?;
            
            return Ok(payload);
        }

        Err(JwtSignError::Invalid)
    }

    fn get_public_key(&self) -> Option<Jwk> {
        self.jwk.to_public_key().ok()
    }

    fn box_clone(&self) -> JwtFactory {
        let clone = Self {
            pem: self.pem.clone(),
            jwk: self.jwk.clone(),
        };

        Box::new(clone)
    }
}
