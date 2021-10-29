#[macro_use]
extern crate rocket;
mod assets;
pub mod jwt;
pub mod oidc;
pub mod prelude;
mod state;

use std::collections::HashMap;
use std::convert::TryInto;

use ::jwt::FromBase64;
use oidc::{ResponseType, TokenRequest};
use prelude::{IStateStore, TokenRequestError};
use rocket::{
    form::Form,
    http::{Cookie, CookieJar, Status},
    outcome::try_outcome,
    request::{FromRequest, Outcome},
    response::{Redirect, Responder},
    serde::{Deserialize, Serialize},
    Build, Request, Rocket, State,
};
use serde_json::json;

pub type ProviderResult<T> = std::result::Result<T, ()>;

#[derive(FromForm, Serialize, Deserialize)]
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
}

type AuthResult<R, T = String> = Result<R, AuthError<T>>;

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
                println!("Auth: {:?}", value);

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
                println!("Credentials: {:?}", credentials);

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

                println!("Username: {:?}", &username);
                println!("Password: {:?}", &password);
                println!("IsValid: {:?}", &is_valid);

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

#[async_trait]
pub trait Providers {
    async fn issue_grant(
        &self,
        sub: &str,
        scopes: &[&str],
        response_types: &[ResponseType],
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

    async fn store_grant(&self, grant: &oidc::Grant, code: &str) -> ProviderResult<()>;
}

type IProviders = Box<dyn Providers + Send + Sync>;

#[get("/")]
async fn index(config: &State<Configuration>) -> String {
    let claims = config
        .providers
        .issue_grant(
            "richbayliss@gmail.com",
            vec!["openid"].as_slice(),
            vec![ResponseType::IdToken].as_slice(),
        )
        .await;

    if let Ok(claims) = claims {
        let token = config.jwt_builder.sign(json!(claims));
        return token;
    }

    "".to_owned()
}

#[get("/connect/authorize?<client_id>&<response_type>&<scope>&<redirect_uri>&<state>")]
async fn authorize(
    client_id: &str,
    response_type: &str,
    scope: &str,
    redirect_uri: &str,
    state: Option<&str>,
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
    bundle.insert("scopes".to_string(), scope.to_string());
    bundle.insert("redirect_uri".to_string(), redirect_uri.to_string());
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
    req: Form<HashMap<&str, &str>>,
    auth: BasicAuthentication,
) -> Result<serde_json::Value, TokenRequestError> {
    let token_req: TokenRequest = req.into_inner().try_into()?;
    println!("Token: {:?}", token_req);

    Ok(json!(""))
}

type SignInBundle = HashMap<String, String>;

fn get_sign_in_bundle(cookies: &CookieJar<'_>) -> Result<SignInBundle, AuthError<String>> {
    let bundle = cookies
        .get_private("sign-in")
        .map(|crumb| crumb.value().to_owned())
        .ok_or(AuthError::Unauthorized("Invalid session".to_owned()))?;

    let bundle: SignInBundle = serde_json::from_str(&bundle).map_err(|err| {
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
) -> AuthResult<serde_json::Value> {
    let bundle = get_sign_in_bundle(cookies)?;

    let sub = config
        .providers
        .validate_login(UsernamePasswordForm {
            username: login.username.to_owned(),
            password: login.password.to_owned(),
        })
        .await
        .map_err(|_| AuthError::Unauthorized("Invalid username or password".to_owned()))?;

    let scopes = match bundle.get("scopes") {
        Some(scopes) => scopes
            .split_whitespace()
            .filter_map(|s| Some(s))
            .collect::<Vec<&str>>(),
        None => Vec::default(),
    };

    let response_types = match bundle.get("response_types") {
        Some(types) => types
            .split_whitespace()
            .filter_map(|s| match s {
                "token" => Some(ResponseType::Token),
                "code" => Some(ResponseType::Code),
                "id_token" => Some(ResponseType::IdToken),
                _ => None,
            })
            .collect::<Vec<ResponseType>>(),
        None => Vec::default(),
    };

    let grant = config
        .providers
        .issue_grant(&sub, scopes.as_slice(), response_types.as_slice())
        .await
        .map_err(|_| AuthError::Unauthorized("Unable to issue grant".to_owned()))?;

    if response_types.contains(&ResponseType::Code) {
        config
            .providers
            .store_grant(&grant, "my-code")
            .await
            .map_err(|_| AuthError::Unauthorized("Could not store the grant".to_owned()))?;
    }

    Ok(json!(grant))
}

fn rocket() -> Rocket<Build> {
    rocket::build()
}

pub async fn start(config: Configuration) -> Result<(), ()> {
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
