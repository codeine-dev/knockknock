use josekit::jwk::alg::rsa::RsaKeyPair;

#[derive(Clone, Debug)]
pub struct Jwk(pub josekit::jwk::Jwk);

impl Jwk {
    pub fn to_public_key(&self) -> Result<Self, anyhow::Error> {
        let public_key = self.0.to_public_key()?;
        Ok(Jwk(public_key))
    }
}

pub type JwtFactory = Box<dyn JwtSign + Send + Sync>;

pub trait JwtSign {
    fn sign(&self, claims: serde_json::Value) -> String;
    fn decode(&self, token: &str) -> Result<serde_json::Value, ()>;
    fn get_key(&self) -> Option<Jwk>;
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
    fn sign(&self, claims: serde_json::Value) -> String {
        todo!()
    }

    fn decode(&self, token: &str) -> Result<serde_json::Value, ()> {
        todo!()
    }

    fn get_key(&self) -> Option<Jwk> {
        self.jwk.to_public_key().ok()
    }
}
