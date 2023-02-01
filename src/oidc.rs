use josekit::jwt::JwtPayload;
use rand::{distributions::Alphanumeric, Rng};
use rocket::{
    http::{ContentType, Status},
    response::Responder,
    serde::{Deserialize, Serialize},
    Request, Response,
};
use serde_json::json;
use std::{
    collections::HashMap,
    convert::TryFrom,
    iter,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::prelude::JwtFactory;

#[derive(PartialEq, Debug, Clone)]
pub enum ResponseType {
    Code,
    Token,
    IdToken,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ReservedClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Grant {
    pub scope: Option<String>,

    #[serde(flatten)]
    pub reserved: ReservedClaims,

    #[serde(flatten)]
    pub claims: serde_json::Value,
}

impl Grant {
    pub fn is_active(&self) -> bool {
        let now = GrantBuilder::now();

        debug!(
            "Token validity: {}-{}-{}",
            self.reserved.nbf, now, self.reserved.exp
        );
        self.reserved.nbf <= now && self.reserved.exp > now
    }
}

impl Into<JwtPayload> for &Grant {
    fn into(self) -> JwtPayload {
        let mut payload = JwtPayload::new();
        

        payload
    }
}

impl From<&JwtPayload> for Grant {
    fn from(value: &JwtPayload) -> Self {
        todo!()
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct GrantResponses {
    pub access_token: Option<Grant>,
    pub id_token: Option<Grant>,
}

impl GrantResponses {
    pub fn to_sealed(&self, signer: &JwtFactory) -> Result<SealedGrantResponses, anyhow::Error> {
        debug!("Sealing grant: {:?}", self);

        let sign_payload = |t: &Grant| {
            debug!("Sealing grant access_token: {:?}", t);
            debug!("Token: {}", json!(t));
            let payload: JwtPayload = t.into();
            signer.sign(&payload)
        };
        
        let access_token = self.access_token.as_ref().map(sign_payload).transpose()?;
        let id_token = self.id_token.as_ref().map(sign_payload).transpose()?;
        
        Ok(SealedGrantResponses {
            access_token,
            id_token,
        })
    }

    pub fn from_sealed(sealed: &SealedGrantResponses, factory: &JwtFactory) -> Result<Self, ()> {
        let access_token: Option<Grant> = sealed.access_token.as_ref().map(|sealed| {
            factory
                .verify(&sealed)
                .ok()
                .map(|v| Grant::from(&v))
                .unwrap()
        });

        let id_token: Option<Grant> = sealed.id_token.as_ref().map(|sealed| {
            factory
                .verify(&sealed)
                .ok()
                .map(|v| Grant::from(&v))
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

pub struct GrantBuilder {
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<String>,
    not_before: Option<u64>,
    not_after: Option<u64>,
    claims: HashMap<String, serde_json::Value>,
    scope: Option<String>,
    nonce: Option<String>,
}

impl GrantBuilder {
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime is set befoe the epoch")
            .as_secs()
    }

    pub fn for_subject(sub: &str) -> Self {
        GrantBuilder {
            issuer: None,
            audience: None,
            not_after: None,
            not_before: Some(Self::now()),
            subject: Some(sub.to_owned()),
            claims: HashMap::new(),
            scope: None,
            nonce: None,
        }
    }

    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_owned());
        self
    }

    pub fn expires_in_secs(mut self, secs: u64) -> Self {
        self.not_after = self.not_before.map(|nbf| nbf + secs);
        self
    }

    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_owned());
        self
    }

    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_owned());
        self
    }

    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scope = Some(scope.to_owned());
        self
    }

    pub fn with_claim<V>(mut self, claim: &str, value: V) -> Self
    where
        serde_json::Value: From<V>,
    {
        self.claims.insert(claim.to_owned(), value.into());
        self
    }
    pub fn build_id_token(self, client_id: &str, issuer: &str) -> Result<Grant, ()> {
        self.with_audience(client_id).with_issuer(issuer).build()
    }

    pub fn build(mut self) -> Result<Grant, ()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime is set befoe the epoch");

        if self.not_after.is_none() {
            self = self.expires_in_secs(10);
        }

        if self.not_before.is_none() {
            self.not_before = Some(now.as_secs());
        }

        let reserved = ReservedClaims {
            iss: self.issuer,
            sub: self.subject,
            aud: self.audience,
            exp: self.not_after.unwrap(),
            nbf: self.not_before.unwrap(),
            iat: now.as_secs(),
            jti: None,
            nonce: None,
        };

        Ok(Grant {
            scope: self.scope,
            reserved,
            claims: json!(self.claims),
        })
    }
}

#[derive(Deserialize, Debug)]
pub enum TokenRequest {
    AuthorizationCode {
        code: String,
        code_verifier: Option<String>,
        redirect_uri: Option<String>,
    },
    ClientCredentials {
        scope: String,
    },
    Password {
        username: String,
        password: String,
        scope: Vec<String>,
    },
    Refresh {
        refresh_token: String,
        redirect_uri: Option<String>,
        scope: String,
    },
}

impl TryFrom<HashMap<String, String>> for TokenRequest {
    type Error = TokenRequestError;

    fn try_from(map: HashMap<String, String>) -> Result<Self, Self::Error> {
        if let Some(grant_type) = map.get("grant_type") {
            return match grant_type.as_str() {
                "authorization_code" => Ok(TokenRequest::AuthorizationCode {
                    code: map
                        .get("code")
                        .map(|s| s.to_owned())
                        .or_else(|| Some("".to_owned()))
                        .unwrap(),
                    code_verifier: map.get("code_verifier").map(|s| s.to_owned()),
                    redirect_uri: map.get("redirect_uri").map(|s| s.to_owned()),
                }),
                _ => Err(TokenRequestError::InvalidGrantType(grant_type.to_owned())),
            };
        }

        Err(TokenRequestError::MissingGrantType)
    }
}

#[derive(Debug)]
pub enum TokenRequestError {
    Unauthorized,
    MissingGrantType,
    InvalidGrantType(String),
    InvalidRedirectUri(String),
    InvalidCode(String),
}

impl TokenRequestError {
    pub fn status_code(&self) -> Status {
        match self {
            Self::Unauthorized => Status::Unauthorized,
            _ => Status::BadRequest,
        }
    }
}

// If the response contains no borrowed data.
impl<'r> Responder<'r, 'static> for TokenRequestError {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let text = match &self {
            Self::Unauthorized => "Unauthorized".to_owned(),
            Self::InvalidGrantType(grant_type) => format!("Invalid grant type: {}", grant_type),
            Self::InvalidRedirectUri(redirect_uri) => {
                format!("Invalid redirect_uri: {}", redirect_uri)
            }
            Self::InvalidCode(code) => {
                format!("Invalid code: {}", code)
            }
            _ => format!("Error: {:?}", self),
        };

        let status = self.status_code();

        Response::build_from(text.respond_to(req)?)
            .status(status)
            .header(ContentType::Plain)
            .ok()
    }
}

#[derive(Debug, Serialize, Default)]
pub struct TokenRequestResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

impl<'r> Responder<'r, 'static> for TokenRequestResponse {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let text = serde_json::to_string(&self).unwrap();

        Response::build_from(text.respond_to(req)?)
            .status(Status::Ok)
            .header(ContentType::JSON)
            .ok()
    }
}

pub fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(20)
        .collect();

    chars
}

#[derive(Serialize)]
pub struct IntrospectResult {
    pub active: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
}

impl IntrospectResult {
    pub fn filter_claims(mut self, claims: Vec<String>) -> Self {
        let filtered_grant = self.grant.map(|grant| {
            let mut grant = grant;
            grant.claims.as_object_mut().map(|grant_claims| {
                *grant_claims = grant_claims
                    .iter()
                    .filter_map(|obj| {
                        if !claims.contains(obj.0) {
                            return None;
                        }

                        Some((obj.0.to_owned(), obj.1.to_owned()))
                    })
                    .collect::<serde_json::Map<String, serde_json::Value>>();
            });

            grant
        });

        self.grant = filtered_grant;

        self
    }
}

impl Default for IntrospectResult {
    fn default() -> Self {
        Self {
            active: false,
            grant: None,
        }
    }
}

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