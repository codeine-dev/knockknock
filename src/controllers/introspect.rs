use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

use crate::prelude::IntrospectResult;
use crate::GrantResponses;
use crate::{guards::auth::BasicAuthentication, prelude::GenericForm, ProviderConfiguration};
use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::serde::Deserialize;
use rocket::{Request, Response, State};
use serde_json::json;

#[derive(Debug)]
pub enum TokenIntrospectError {
    Unauthorized,
    MissingToken,
}

impl TokenIntrospectError {
    pub fn status_code(&self) -> Status {
        match self {
            Self::Unauthorized => Status::Unauthorized,
            _ => Status::BadRequest,
        }
    }
}

// If the response contains no borrowed data.
impl<'r> Responder<'r, 'static> for TokenIntrospectError {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let text = match &self {
            Self::Unauthorized => "Unauthorized".to_owned(),
            _ => format!("Error: {:?}", self),
        };

        let status = self.status_code();

        Response::build_from(text.respond_to(req)?)
            .status(status)
            .header(ContentType::Plain)
            .ok()
    }
}

#[derive(Deserialize, Debug)]
pub enum TokenIntrospectRequest {
    AccessToken { token: String },
}

impl TryFrom<HashMap<String, String>> for TokenIntrospectRequest {
    type Error = TokenIntrospectError;

    fn try_from(map: HashMap<String, String>) -> Result<Self, Self::Error> {
        match map.get("token") {
            Some(token) => Ok(Self::AccessToken {
                token: String::from(token),
            }),
            _ => Err(TokenIntrospectError::MissingToken),
        }
    }
}

#[post("/introspect", data = "<req>")]
pub async fn introspect(
    config: &State<ProviderConfiguration>,
    req: GenericForm,
    auth: BasicAuthentication,
) -> Result<serde_json::Value, TokenIntrospectError> {
    let token_req: TokenIntrospectRequest = req.into_inner().try_into()?;
    debug!("Token: {:?}", token_req);

    let token = match token_req {
        TokenIntrospectRequest::AccessToken { token } => {
            let grants = config
                .adaptor
                .retrieve_grant(&token)
                .await
                .map_err(|_| TokenIntrospectError::MissingToken)?;

            let tokens = GrantResponses::from_sealed(&grants, &config.jwt)
                .map_err(|_| TokenIntrospectError::Unauthorized)?;

            match tokens.access_token {
                Some(grant) => match grant.is_active() {
                    true => Some(IntrospectResult {
                        active: true,
                        grant: Some(grant),
                    }),
                    false => Some(IntrospectResult::default()),
                },
                None => None,
            }
        }
    };

    let claims: Vec<String> = async {
        let scopes = config.adaptor.scopes_for_resource(&auth.username).await;

        let mut claims: Vec<String> = Vec::default();

        for scope in scopes {
            config
                .adaptor
                .claims_for_scope(&scope)
                .await
                .iter()
                .for_each(|claim| {
                    if !claims.contains(claim) {
                        claims.push(claim.clone());
                    }
                });
        }

        claims
    }
    .await;

    debug!("Claims to filter: {:?}", claims);

    match token {
        Some(token) => Ok(json!(token.filter_claims(claims))),
        None => Err(TokenIntrospectError::Unauthorized),
    }
}
