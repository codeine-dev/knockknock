#[macro_use]
pub extern crate rocket;
mod assets;
mod controllers;
mod guards;
mod jwt;
mod oidc;
pub mod prelude;
mod traits;
mod types;

use prelude::*;

pub type ProviderResult<T> = std::result::Result<T, ()>;

pub struct ProviderConfiguration {
    pub mountpoint: Mountpoint,
    pub jwt: jwt::JwtFactory,
    pub adaptor: OidcAdaptor,
}