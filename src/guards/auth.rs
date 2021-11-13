use rocket::{
    http::Status,
    outcome::try_outcome,
    request::{FromRequest, Outcome},
    Request, State,
};

use crate::ProviderConfiguration;

pub struct BasicAuthentication {
    pub username: String,
    pub password: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BasicAuthentication {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config: &State<ProviderConfiguration> =
            try_outcome!(req.guard::<&State<ProviderConfiguration>>().await);

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
                    .adaptor
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
