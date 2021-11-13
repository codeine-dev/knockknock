use crate::{SealedGrantResponses, controllers::{account::{UsernamePasswordForm, }, authorization::ClientAuthBundle}, guards::headers::RequestHost, oidc, prelude::{ResponseType}};

pub type AdaptorResult<T> = std::result::Result<T, ()>;

#[rocket::async_trait]
pub trait OidcAdaptorImpl {

    async fn issue_grant(
        &self,
        sub: &str,
        scopes: &[&str],
        response_type: ResponseType,
        request: &RequestHost,
        auth_bundle: &ClientAuthBundle,
    ) -> AdaptorResult<oidc::Grant>;

    async fn claims_for_scope(&self, scope: &str) -> Vec<String>;

    async fn scopes_for_resource(&self, resource: &str) -> Vec<String>;

    async fn validate_login(&self, login: UsernamePasswordForm) -> AdaptorResult<String>;

    async fn validate_client(&self, client_id: &str, client_secret: &str) -> AdaptorResult<()>;

    async fn validate_authorization(
        &self,
        client_id: &str,
        response_type: &[oidc::ResponseType],
        scope: &[&str],
        redirect_url: &str,
        state: Option<&str>,
    ) -> Result<(), String>;

    async fn store_grant(&self, grant: &SealedGrantResponses, code: &str) -> AdaptorResult<()>;

    async fn retrieve_grant(&self, code: &str) -> AdaptorResult<SealedGrantResponses>;
}

