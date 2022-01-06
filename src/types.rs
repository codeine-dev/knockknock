pub struct Mountpoint(String);

impl Mountpoint {
    pub fn get_path(&self) -> String {
        self.0.clone()
    }
}

impl Default for Mountpoint {
    fn default() -> Self {
        Self("/connect".to_owned())
    }
}