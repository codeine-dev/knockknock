use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request,
};

pub struct RequestHost {
    pub host: String,
    pub scheme: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestHost {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let scheme = request
            .headers()
            .get_one("X-Forwarded-Proto")
            .map(|s| s.to_owned())
            .or_else(|| Some("http".to_owned()))
            .unwrap();

        let host = request
            .headers()
            .get_one("Host")
            .map(|host| host.to_owned());

        match host {
            Some(host) => {
                // check validity
                Outcome::Success(Self { host, scheme })
            }
            // token does not exist
            None => Outcome::Failure((Status::BadRequest, ())),
        }
    }
}
