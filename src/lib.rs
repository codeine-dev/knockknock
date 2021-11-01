#[macro_use]
extern crate rocket;
mod assets;
mod fern;
pub mod jwt;
pub mod oidc;
pub mod prelude;
mod state;

use std::collections::HashMap;
use std::convert::TryInto;

use oidc::{ResponseType, TokenRequest, TokenRequestResponse};
use prelude::{Grant, IStateStore, TokenRequestError};
use rocket::{
    form::Form,
    http::{ContentType, Cookie, CookieJar, Status},
    outcome::try_outcome,
    request::{FromRequest, Outcome},
    response::{Redirect, Responder},
    serde::{Deserialize, Serialize},
    Build, Request, Response, Rocket, State,
};
use serde_json::json;

pub type ProviderResult<T> = std::result::Result<T, ()>;

#[derive(FromForm, Serialize, Deserialize, Debug)]
pub struct UsernamePasswordForm {
    pub username: String,
    pub password: String,
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

#[derive(Responder, Debug)]
pub enum AuthError<T> {
    #[response(status = 401)]
    Unauthorized(T),
    #[response(status = 400)]
    InvalidRequest(T),
}

type AuthResult<R, T = String> = Result<R, AuthError<T>>;

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ValidAuthResult {
    SimpleResult(String),
    TokenResult {
        redirect_uri: String,
        #[serde(skip_serializing)]
        id_token: Option<String>,
        #[serde(skip_serializing)]
        access_token: Option<String>,
        #[serde(skip_serializing)]
        state: Option<String>,
        #[serde(skip_serializing)]
        code: Option<String>,
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
                code,
            } => ValidAuthResult::SimpleResult(format!(
                "{}#access_token={}&id_token={}&state={}&code={}",
                redirect_uri,
                access_token.or(Some("".to_owned())).unwrap(),
                id_token.or(Some("".to_owned())).unwrap(),
                state.or(Some("".to_owned())).unwrap(),
                code.or(Some("".to_owned())).unwrap(),
            )),
            _ => self,
        };

        let body = serde_json::to_string(&res).unwrap();

        Response::build_from(body.respond_to(req)?)
            .status(Status::Ok)
            .header(ContentType::JSON)
            .ok()
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct GrantResponses {
    pub access_token: Option<Grant>,
    pub id_token: Option<Grant>,
}

impl GrantResponses {
    pub fn to_sealed(&self, signer: &Box<dyn jwt::JwtSign + Sync + Send>) -> SealedGrantResponses {
        SealedGrantResponses {
            access_token: self.access_token.as_ref().map(|t| signer.sign(json!(t))),
            id_token: self.id_token.as_ref().map(|t| signer.sign(json!(t))),
            ..Default::default()
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct SealedGrantResponses {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
}

pub struct BasicAuthentication {
    pub username: String,
    pub password: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BasicAuthentication {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config: &State<Configuration> =
            try_outcome!(req.guard::<&State<Configuration>>().await);

        match req.headers().get_one("Authorization") {
            Some(auth) => {
                let value = String::from(&auth[6..]);

                let credentials = base64::decode(&value)
                    .map(|b| {
                        String::from_utf8(b)
                            .or::<String>(Ok(String::default()))
                            .unwrap()
                    })
                    .map_err(|_| Outcome::Failure((Status::Unauthorized, ())));

                if let Err(bad_format) = credentials {
                    return bad_format;
                }
                let credentials = credentials.unwrap();

                let parts = credentials
                    .split(":")
                    .map(|s| s.to_owned())
                    .collect::<Vec<String>>();

                let mut iter = parts.iter();

                let username = iter
                    .next()
                    .map(|s| s.to_owned())
                    .or(Some("".to_owned()))
                    .unwrap();
                let password = iter
                    .next()
                    .map(|s| s.to_owned())
                    .or(Some("".to_owned()))
                    .unwrap();

                let is_valid = config
                    .providers
                    .validate_client(&username, &password)
                    .await
                    .map(|_| true)
                    .or::<bool>(Ok(false))
                    .unwrap();

                match is_valid {
                    true => Outcome::Success(BasicAuthentication { username, password }),
                    _ => Outcome::Failure((Status::Unauthorized, ())),
                }
            }
            _ => Outcome::Failure((Status::Unauthorized, ())),
        }
    }
}

pub struct Configuration {
    pub jwt_builder: jwt::JwtBuilder,
    pub providers: IProviders,
    pub state_store: IStateStore,
}

pub struct AuthRequest {
    pub host: String,
    pub client_id: Option<String>,
    pub nonce: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthRequest {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let host = request
            .headers()
            .get_one("Host")
            .map(|host| host.to_owned());

        let scheme = request
            .headers()
            .get_one("X-Forwarded-Proto")
            .map(|s| s.to_owned())
            .or_else(|| Some("http".to_owned()))
            .unwrap();

        match host {
            Some(host) => {
                // check validity
                Outcome::Success(Self {
                    host: format!("{}://{}", scheme, host),
                    client_id: None,
                    nonce: None,
                })
            }
            // token does not exist
            None => Outcome::Failure((Status::BadRequest, ())),
        }
    }
}

#[async_trait]
pub trait Providers {
    async fn issue_grant(
        &self,
        sub: &str,
        scopes: &[&str],
        response_type: ResponseType,
        request: &AuthRequest,
    ) -> ProviderResult<oidc::Grant>;

    async fn validate_login(&self, login: UsernamePasswordForm) -> ProviderResult<String>;

    async fn validate_client(&self, client_id: &str, client_secret: &str) -> ProviderResult<()>;

    async fn validate_authorization(
        &self,
        client_id: &str,
        response_type: &[oidc::ResponseType],
        scope: &[&str],
        redirect_url: &str,
        state: Option<&str>,
    ) -> Result<(), String>;

    async fn store_grant(&self, grant: &SealedGrantResponses, code: &str) -> ProviderResult<()>;

    async fn retrieve_grant(&self, code: &str) -> ProviderResult<SealedGrantResponses>;
}

type IProviders = Box<dyn Providers + Send + Sync>;

#[get("/")]
async fn index(config: &State<Configuration>, req: AuthRequest) -> String {
    "".to_owned()
}

#[get("/connect/authorize?<client_id>&<response_type>&<scope>&<redirect_uri>&<state>&<nonce>")]
async fn authorize(
    client_id: &str,
    response_type: &str,
    scope: &str,
    redirect_uri: &str,
    state: Option<&str>,
    nonce: Option<&str>,
    config: &State<Configuration>,
    cookies: &CookieJar<'_>,
) -> Redirect {
    let response_types: Vec<ResponseType> = response_type
        .split_whitespace()
        .filter_map(|rt| match rt {
            "code" => Some(ResponseType::Code),
            "token" => Some(ResponseType::Token),
            "id_token" => Some(ResponseType::IdToken),
            _ => None,
        })
        .collect();

    let scopes: Vec<&str> = scope.split_whitespace().collect();

    // validate the client is making an acceptable request
    if let Err(reason) = config
        .providers
        .validate_authorization(
            client_id,
            response_types.as_slice(),
            scopes.as_slice(),
            redirect_uri,
            state,
        )
        .await
    {
        return Redirect::to(format!("/error?reason={:?}", reason));
    };

    let mut bundle = SignInBundle::new();
    bundle.insert("client_id".to_string(), client_id.to_string());
    bundle.insert("response_type".to_string(), response_type.to_string());
    bundle.insert("scope".to_string(), scope.to_string());
    bundle.insert("redirect_uri".to_string(), redirect_uri.to_string());
    bundle.insert(
        "nonce".to_string(),
        nonce.or_else(|| Some("")).unwrap().to_string(),
    );
    bundle.insert(
        "state".to_string(),
        state.or_else(|| Some("")).unwrap().to_string(),
    );

    let bundle = serde_json::to_string(&json!(bundle)).unwrap();

    cookies.add_private(Cookie::new("sign-in", bundle));

    // redirect to the login page OR an error page
    Redirect::to("/assets/sign-in.html")
}

#[post("/connect/token", data = "<req>")]
async fn token(
    config: &State<Configuration>,
    req: Form<HashMap<&str, &str>>,
    auth: BasicAuthentication,
) -> Result<oidc::TokenRequestResponse, TokenRequestError> {
    let token_req: TokenRequest = req.into_inner().try_into()?;
    debug!("Token: {:?}", token_req);

    let grants = match token_req {
        TokenRequest::AuthorizationCode {
            code,
            code_verifier,
            redirect_uri,
        } => {
            let grants = config
                .providers
                .retrieve_grant(&code)
                .await
                .map_err(|_| TokenRequestError::InvalidCode(code))?;
            Some(grants)
        }
        _ => None,
    };

    match grants {
        Some(grants) => Ok(TokenRequestResponse {
            access_token: grants.access_token,
            id_token: grants.id_token,
            refresh_token: None,
        }),
        None => Err(TokenRequestError::Unauthorized),
    }
}

type SignInBundle = HashMap<String, String>;

fn get_sign_in_bundle(cookies: &CookieJar<'_>) -> Result<SignInBundle, AuthError<String>> {
    let bundle = cookies
        .get_private("sign-in")
        .map(|crumb| crumb.value().to_owned())
        .ok_or(AuthError::Unauthorized("Invalid session".to_owned()))?;

    let bundle: SignInBundle = serde_json::from_str(&bundle).map_err(|err| {
        debug!("Failed to decode sign-in bundle cookie: {:?}", err);
        let reason = format!("Bad session: {:?}", err);
        AuthError::Unauthorized(reason)
    })?;

    Ok(bundle)
}

#[get("/sign-in")]
async fn sign_in(
    _config: &State<Configuration>,
    cookies: &CookieJar<'_>,
) -> AuthResult<serde_json::Value> {
    let bundle = get_sign_in_bundle(cookies)?;
    Ok(json!(bundle))
}

#[post("/sign-in", data = "<login>")]
async fn sign_in_post(
    config: &State<Configuration>,
    cookies: &CookieJar<'_>,
    login: Form<UsernamePasswordForm>,
    mut req: AuthRequest,
) -> AuthResult<ValidAuthResult> {
    let bundle = get_sign_in_bundle(cookies)?;

    let client_id = bundle.get("client_id").map(|s| s.to_owned());
    req.client_id = client_id;

    let redirect_uri = bundle.get("redirect_uri").map(|s| s.to_owned());
    if redirect_uri.is_none() {
        return Err(AuthError::InvalidRequest(
            "Redirect URI is missing".to_owned(),
        ));
    }
    let redirect_uri = redirect_uri.unwrap();

    let state = bundle.get("state").map(|s| s.to_owned());
    let nonce = bundle.get("nonce").map(|s| s.to_owned());

    let sub = config
        .providers
        .validate_login(UsernamePasswordForm {
            username: login.username.to_owned(),
            password: login.password.to_owned(),
        })
        .await
        .map_err(|_| {
            debug!("Invalid username or password: {:?}", login);
            AuthError::Unauthorized("Invalid username or password".to_owned())
        })?;

    let scopes = match bundle.get("scope") {
        Some(scopes) => scopes
            .split_whitespace()
            .filter_map(|s| Some(s))
            .collect::<Vec<&str>>(),
        None => Vec::default(),
    };

    let response_types = match bundle.get("response_type") {
        Some(types) => types
            .split_whitespace()
            .map(|s| {
                debug!("ResponseType: {}", s);
                s
            })
            .filter_map(|s| match s {
                "code" => Some(ResponseType::Code),
                "token" => Some(ResponseType::Token),
                "id_token" => Some(ResponseType::IdToken),
                _ => None,
            })
            .collect::<Vec<ResponseType>>(),
        None => Vec::default(),
    };

    let mut grants = GrantResponses::default();
    for response_type in response_types.clone() {
        debug!(
            "Issuing grant for sub: {}, withScope: {:?}, forResponseType: {:?}",
            sub, scopes, response_type
        );

        let mut grant = config
            .providers
            .issue_grant(&sub, scopes.as_slice(), response_type.clone(), &req)
            .await
            .map_err(|err| {
                debug!("Failed to issue_grant: {:?}", err);
                AuthError::Unauthorized("Unable to issue grant".to_owned())
            })?;

        if nonce.is_some() {
            grant.reserved.nonce = Some(nonce.as_ref().unwrap().to_owned());
        }

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

    if response_types.contains(&ResponseType::Code) {
        let sealed_grant = grants.to_sealed(&config.jwt_builder);
        config
            .providers
            .store_grant(&sealed_grant, "my-code")
            .await
            .map_err(|_| AuthError::Unauthorized("Could not store the grant".to_owned()))?;
    }

    let access_token = grants
        .access_token
        .map(|grant| config.jwt_builder.sign(json!(grant)));
    let id_token = grants
        .id_token
        .map(|grant| config.jwt_builder.sign(json!(grant)));

    Ok(ValidAuthResult::TokenResult {
        redirect_uri,
        access_token,
        id_token,
        state,
        code: Some("my-code".to_owned()),
    })
}

fn rocket() -> Rocket<Build> {
    rocket::build()
}

pub async fn start(config: Configuration) -> Result<(), ()> {
    fern::setup_logger(log::LevelFilter::Debug).map_err(|_| ())?;

    rocket()
        .manage(config)
        .mount(
            "/",
            routes![
                index,
                authorize,
                token,
                sign_in,
                sign_in_post,
                assets::assets
            ],
        )
        .launch()
        .await
        .map_err(|_| ())
}
