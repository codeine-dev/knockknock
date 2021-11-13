use rocket::http::Cookie;
use rocket::serde::{Deserialize, Serialize};
use rocket::{http::CookieJar, response::Redirect, State};

use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientAuthBundle {
    pub client_id: String,
    pub response_type: String,
    pub scope: String,
    pub redirect_uri: String,
    pub nonce: Option<String>,
    pub state: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientAuthBundleOption {
    Valid { bundle: ClientAuthBundle },
    Missing,
    Invalid,
}

impl ClientAuthBundleOption {
    pub fn new(
        client_id: &str,
        response_type: &str,
        scope: &str,
        redirect_uri: &str,
        nonce: Option<&str>,
        state: Option<&str>,
    ) -> Self {
        Self::Valid {
            bundle: ClientAuthBundle {
                client_id: client_id.to_owned(),
                response_type: response_type.to_owned(),
                scope: scope.to_owned(),
                redirect_uri: redirect_uri.to_owned(),
                nonce: nonce.map(|s| s.to_owned()),
                state: state.map(|s| s.to_owned()),
            },
        }
    }

    pub fn save_to_cookies(&self, cookies: &CookieJar<'_>) {
        let bundle = serde_json::to_string(&self).unwrap();
        cookies.add_private(Cookie::new("ClientAuthBundle", bundle));
    }
}

impl From<&CookieJar<'_>> for ClientAuthBundleOption {
    fn from(cookies: &CookieJar<'_>) -> Self {
        let bundle = cookies
            .get_private("ClientAuthBundle")
            .map(|crumb| crumb.value().to_owned());

        if bundle.is_none() {
            return Self::Missing;
        }

        match serde_json::from_str::<Self>(&bundle.unwrap()) {
            Ok(bundle) => bundle,
            _ => Self::Invalid,
        }
    }
}

#[get("/connect/authorize?<client_id>&<response_type>&<scope>&<redirect_uri>&<state>&<nonce>")]
pub async fn authorize(
    client_id: &str,
    response_type: &str,
    scope: &str,
    redirect_uri: &str,
    state: Option<&str>,
    nonce: Option<&str>,
    config: &State<ProviderConfiguration>,
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
        .adaptor
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

    let bundle =
        ClientAuthBundleOption::new(client_id, response_type, scope, redirect_uri, nonce, state);
    bundle.save_to_cookies(cookies);

    // redirect to the login page OR an error page
    Redirect::to("/assets/sign-in.html")
}
