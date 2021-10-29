use rocket::response::Redirect;
use urlencoding::encode;

pub type IStateStore = Box<dyn StateStore + Sync + Send>;

#[derive(Debug)]
pub enum StateStoreError {
    SetStateError { reason: Option<String> },
    KeyNotFound { key: String },
}

impl Into<String> for StateStoreError {
    fn into(self) -> String {
        match self {
            Self::KeyNotFound { key } => format!("KeyNotFound: {}", key),
            Self::SetStateError { reason } => format!(
                "SetStateError: {}",
                reason.or_else(|| Some("Unknown".to_owned())).unwrap()
            ),
        }
    }
}

impl Into<Redirect> for StateStoreError {
    fn into(self) -> Redirect {
        let reason: String = self.into();
        Redirect::to(format!("/error?reason={}", encode(&reason)))
    }
}

pub type StateStoreResult<T> = std::result::Result<T, self::StateStoreError>;

#[async_trait]
pub trait StateStore {
    fn build(&self) -> IStateStore;
    async fn get_state(&self, key: &str) -> StateStoreResult<String>;
    async fn set_state(&self, value: &str) -> StateStoreResult<String>;
}
