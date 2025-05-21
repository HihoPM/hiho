use crate::error::PasswordError;

pub struct PasswordValidator;

impl PasswordValidator {
    pub fn validate(password: &str) -> Result<(), PasswordError> {
        if password.len() < 8 {
            return Err(PasswordError::TooShort);
        }
        if !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(PasswordError::NoDigits);
        }
        if !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(PasswordError::NoUppercase);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn strength(password: &str) -> u8 {
        let mut score = 0;
        if password.len() >= 8 { score += 1 }
        if password.chars().any(|c| c.is_ascii_digit()) { score += 1 }
        if password.chars().any(|c| c.is_ascii_uppercase()) { score += 1 }
        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate() {
        assert!(PasswordValidator::validate("Weak1").is_err());
        assert!(PasswordValidator::validate("StrongPass123").is_ok());
    }
}