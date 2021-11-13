use rocket::http::{ContentType, Status};
use rocket::serde::{Deserialize, Serialize};
use rocket::{form::Form, http::CookieJar, response::Responder, State};
use rocket::{Request, Response};
use serde_json::json;

use crate::prelude::ResponseType;
use crate::{
    controllers::authorization::ClientAuthBundleOption, guards::headers::RequestHost,
    ProviderConfiguration,
};
use crate::{oidc, GrantResponses};

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ValidAuthResult {
    SimpleResult(String),
    AuthCodeResult {
        redirect_uri: String,
        #[serde(skip_serializing)]
        state: Option<String>,
        #[serde(skip_serializing)]
        code: String,
    },
    TokenResult {
        redirect_uri: String,
        #[serde(skip_serializing)]
        id_token: Option<String>,
        #[serde(skip_serializing)]
        access_token: Option<String>,
        #[serde(skip_serializing)]
        state: Option<String>,
    },
}

impl<'r> Responder<'r, 'static> for ValidAuthResult {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let res = match self {
            ValidAuthResult::TokenResult {
                redirect_uri,
                id_token,
                access_token,
                state,
            } => {
                let parts: Vec<String> = [
                    ("access_token", access_token),
                    ("id_token", id_token),
                    ("state", state),
                ]
                .iter()
                .filter_map(|s| match s {
                    (label, Some(value)) => Some(format!("{}={}", label, value)),
                    _ => None,
                })
                .collect();
                let query = parts.join("&");
                ValidAuthResult::SimpleResult(format!("{}#{}", redirect_uri, query))
            }
            ValidAuthResult::AuthCodeResult {
                redirect_uri,
                state,
                code,
            } => {
                let parts: Vec<String> = [("code", Some(code)), ("state", state)]
                    .iter()
                    .filter_map(|s| match s {
                        (label, Some(value)) => Some(format!("{}={}", label, value)),
                        _ => None,
                    })
                    .collect();
                let query = parts.join("&");
                ValidAuthResult::SimpleResult(format!("{}#{}", redirect_uri, query))
            }
            _ => self,
        };

        let body = serde_json::to_string(&res).unwrap();

        Response::build_from(body.respond_to(req)?)
            .status(Status::Ok)
            .header(ContentType::JSON)
            .ok()
    }
}

#[derive(Responder, Debug)]
pub enum AuthError<T> {
    #[response(status = 401)]
    Unauthorized(T),
    #[response(status = 400)]
    InvalidRequest(T),
}

type AuthResult<R, T = String> = Result<R, AuthError<T>>;

#[derive(FromForm, Serialize, Deserialize, Debug)]
pub struct UsernamePasswordForm {
    pub username: String,
    pub password: String,
}

#[post("/sign-in", data = "<login>")]
pub async fn sign_in_post(
    config: &State<ProviderConfiguration>,
    cookies: &CookieJar<'_>,
    login: Form<UsernamePasswordForm>,
    req: RequestHost,
) -> AuthResult<ValidAuthResult> {
    let bundle: ClientAuthBundleOption = cookies.into();
    let bundle = match bundle {
        ClientAuthBundleOption::Valid { bundle } => Ok(bundle),
        _ => Err(AuthError::InvalidRequest(
            "Bad or missing authentication bundle".to_owned(),
        )),
    }?;

    let sub = config
        .adaptor
        .validate_login(UsernamePasswordForm {
            username: login.username.to_owned(),
            password: login.password.to_owned(),
        })
        .await
        .map_err(|_| {
            debug!("Invalid username or password: {:?}", login);
            AuthError::Unauthorized("Invalid username or password".to_owned())
        })?;

    let scopes = &bundle
        .scope
        .split_whitespace()
        .filter_map(|s| Some(s))
        .collect::<Vec<&str>>();

    let response_types = &bundle
        .response_type
        .split_whitespace()
        .filter_map(|s| match s {
            "code" => Some(ResponseType::Code),
            "token" => Some(ResponseType::Token),
            "id_token" => Some(ResponseType::IdToken),
            _ => None,
        })
        .collect::<Vec<ResponseType>>();

    // ensure we have either a token OR id_token response type requested
    if !response_types
        .iter()
        .any(|rt| rt == &ResponseType::IdToken || rt == &ResponseType::Token)
    {
        return Err(AuthError::InvalidRequest(
            "Must specify either token or id_token responses when authorizing".to_owned(),
        ));
    };

    let mut grants = GrantResponses::default();
    for response_type in response_types.clone() {
        debug!(
            "Issuing grant for sub: {}, withScope: {:?}, forResponseType: {:?}",
            sub, scopes, response_type
        );

        let mut grant = config
            .adaptor
            .issue_grant(
                &sub,
                scopes.as_slice(),
                response_type.clone(),
                &req,
                &bundle,
            )
            .await
            .map_err(|err| {
                debug!("Failed to issue_grant: {:?}", err);
                AuthError::Unauthorized("Unable to issue grant".to_owned())
            })?;

        if bundle.nonce.is_some() {
            grant.reserved.nonce = Some(bundle.nonce.as_ref().unwrap().to_owned());
        }

        debug!("Grant: {:?}", grant);

        match response_type {
            ResponseType::Token => {
                grants.access_token = Some(grant);
            }
            ResponseType::IdToken => {
                grants.id_token = Some(grant);
            }
            _ => {}
        }
    }

    let auth_code = oidc::generate_authorization_code();
    let sealed_grant = grants.to_sealed(&config.jwt_builder);
    debug!("Sealed grants: {:?}", sealed_grant);

    config
        .adaptor
        .store_grant(&sealed_grant, &auth_code)
        .await
        .map_err(|_| AuthError::Unauthorized("Could not store the grant".to_owned()))?;

    let access_token = Some(String::from(&auth_code));

    let redirect_uri = bundle.redirect_uri.to_owned();
    let state = bundle.state.to_owned();

    if response_types.contains(&ResponseType::Code) {
        return Ok(ValidAuthResult::AuthCodeResult {
            redirect_uri,
            state,
            code: access_token.unwrap(),
        });
    }

    let id_token = grants
        .id_token
        .map(|grant| config.jwt_builder.sign(json!(grant)));

    Ok(ValidAuthResult::TokenResult {
        redirect_uri,
        state,
        access_token,
        id_token,
    })
}
