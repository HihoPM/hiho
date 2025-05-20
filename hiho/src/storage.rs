use std::fs::OpenOptions;
use std::io::Write;
use crate::error::PasswordError;

pub struct PasswordStorage;

impl PasswordStorage {
    pub fn save(password: &str, filename: &str) -> Result<(), PasswordError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)?;

        writeln!(file, "{}", password)?;
        file.sync_all()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn load(filename: &str) -> Result<Vec<String>, PasswordError> {
        Ok(std::fs::read_to_string(filename)?
            .lines()
            .map(|line| line.to_string())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_save_load() {
        let file = NamedTempFile::new().unwrap();
        PasswordStorage::save("test", file.path().to_str().unwrap()).unwrap();
        let data = PasswordStorage::load(file.path().to_str().unwrap()).unwrap();
        assert_eq!(data, vec!["test"]);
    }
}