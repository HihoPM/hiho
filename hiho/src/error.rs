use std::fmt;
use serde_json;

#[derive(Debug)]
pub enum PasswordError {
    TooShort,
    NoDigits,
    NoUppercase,
    IoError(std::io::Error),
    JsonError(serde_json::Error),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "Пароль должен содержать ≥8 символов"),
            Self::NoDigits => write!(f, "Пароль должен содержать цифры"),
            Self::NoUppercase => write!(f, "Пароль должен содержать заглавные буквы"),
            Self::IoError(e) => write!(f, "Ошибка ввода-вывода: {}", e),
            Self::JsonError(e) => write!(f, "Ошибка JSON: {}", e),
        }
    }
}

impl From<std::io::Error> for PasswordError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<serde_json::Error> for PasswordError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err)
    }
}