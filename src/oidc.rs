use rocket::{
    form::Lenient,
    http::{ContentType, Status},
    outcome::try_outcome,
    request::{FromRequest, Outcome},
    response::Responder,
    serde::{Deserialize, Serialize},
    Request, Response,
};
use serde_json::json;
use std::{
    collections::HashMap,
    convert::TryFrom,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(PartialEq)]
pub enum ResponseType {
    Code,
    Token,
    IdToken,
}

#[derive(Debug, Serialize, Default)]
pub struct ReservedClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Grant {
    #[serde(flatten)]
    pub reserved: ReservedClaims,

    #[serde(flatten)]
    pub claims: serde_json::Value,
}

pub struct GrantBuilder {
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<String>,
    not_before: Option<u64>,
    not_after: Option<u64>,
    claims: HashMap<String, serde_json::Value>,
}

impl GrantBuilder {
    fn now() -> u64 {
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
        }
    }

    pub fn with_claim<V>(mut self, claim: &str, value: V) -> Self
    where
        serde_json::Value: From<V>,
    {
        self.claims.insert(claim.to_owned(), value.into());
        self
    }

    pub fn build(self) -> Result<Grant, ()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime is set befoe the epoch");

        let reserved = ReservedClaims {
            iss: self.issuer,
            sub: self.subject,
            aud: self.audience,
            exp: self.not_after,
            nbf: self.not_before,
            iat: Some(now.as_secs()),
            jti: None,
        };

        Ok(Grant {
            reserved,
            claims: json!(self.claims),
        })
    }
}

#[derive(Deserialize, Debug)]
pub enum TokenRequest {
    AuthorizationCode {
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

impl TryFrom<HashMap<&str, &str>> for TokenRequest {
    type Error = TokenRequestError;

    fn try_from(map: HashMap<&str, &str>) -> Result<Self, Self::Error> {
        if let Some(&grant_type) = map.get("grant_type") {
            return match grant_type {
                "code" => Ok(TokenRequest::AuthorizationCode {
                    code_verifier: map.get("code_verifier").map(|&s| s.to_owned()),
                    redirect_uri: map.get("redirect_uri").map(|&s| s.to_owned()),
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
            _ => format!("Error: {:?}", self),
        };

        let status = self.status_code();

        Response::build_from(text.respond_to(req)?)
            .status(status)
            .header(ContentType::Plain)
            .ok()
    }
}
