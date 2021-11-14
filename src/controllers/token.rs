use std::convert::TryInto;

use oidc::{TokenRequest, TokenRequestError, TokenRequestResponse};
use rocket::State;

use crate::{guards::auth::BasicAuthentication, oidc, prelude::GenericForm, ProviderConfiguration};

#[post("/token", data = "<req>")]
pub async fn token(
    config: &State<ProviderConfiguration>,
    req: GenericForm,
    _auth: BasicAuthentication,
) -> Result<TokenRequestResponse, TokenRequestError> {
    let token_req: TokenRequest = req.into_inner().try_into()?;
    debug!("Token: {:?}", token_req);

    let grants = match token_req {
        TokenRequest::AuthorizationCode {
            code,
            code_verifier: _,
            redirect_uri: _,
        } => {
            let grants = config
                .adaptor
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
