use crate::{error::PasswordError, crypto::Crypto};

pub struct PasswordStorage {
    crypto: Crypto,
}

impl PasswordStorage {
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    pub fn save(&self, password: &str, filename: &str) -> Result<(), PasswordError> {
        let encrypted = self.crypto.encrypt(password);
        std::fs::write(filename, encrypted)?;
        Ok(())
    }

    pub fn load(&self, filename: &str) -> Result<Vec<String>, PasswordError> {
        let data = std::fs::read(filename)?;
        Ok(vec![self.crypto.decrypt(&data)])
    }
}