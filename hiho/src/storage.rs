use crate::crypto::Crypto;
use crate::error::PasswordError;
use crate::credential::Credential;
use std::fs;

pub struct PasswordStorage {
    crypto: Crypto,
}

impl PasswordStorage {
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    pub fn save(&self, credentials: &[Credential], filename: &str) -> Result<(), PasswordError> {
        let json = serde_json::to_vec(credentials)?;
        let encrypted = self.crypto.encrypt(&json);
        fs::write(filename, encrypted)?;
        Ok(())
    }

    pub fn load(&self, filename: &str) -> Result<Vec<Credential>, PasswordError> {
        let data = fs::read(filename)?;
        let decrypted = self.crypto.decrypt(&data);
        let credentials = serde_json::from_str(&decrypted)?;
        Ok(credentials)
    }
}