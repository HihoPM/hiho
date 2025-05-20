mod error;
mod password;
mod storage;

use crate::error::PasswordError;
use crate::password::PasswordValidator;
use crate::storage::PasswordStorage;
use std::io;

fn main() -> Result<(), PasswordError> {
    println!("🔒 Менеджер паролей v0.1");

    loop {
        println!("\nВведите пароль (или 'exit' для выхода):");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("exit") {
            break;
        }

        match PasswordValidator::validate(input) {
            Ok(_) => {
                PasswordStorage::save(input, "passwords.txt")?;
                println!("✅ Пароль сохранен. Уровень сложности: {}/3", 
                    PasswordValidator::strength(input));
            },
            Err(e) => eprintln!("❌ Ошибка: {}", e),
        }
    }

    Ok(())
}