use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    pub site: String,
    pub login: String,
    pub password: String,
}

impl Credential {
    pub fn new(site: &str, login: &str, password: &str) -> Self {
        Self {
            site: site.to_string(),
            login: login.to_string(),
            password: password.to_string(),
        }
    }
}