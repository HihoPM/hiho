mod error;
mod password;
mod storage;
mod crypto;

use crate::crypto::Crypto;
use crate::error::PasswordError;
use crate::password::PasswordValidator;
use crate::storage::PasswordStorage;
use std::io;

fn main() -> Result<(), PasswordError> {
    println!("🔒 Менеджер паролей v0.1");

    let crypto = Crypto::new();
    println!("Сгенерирован ключ шифрования: {}", crypto.get_key_hex());
    println!("IV: {}", crypto.get_iv_hex());

    // Инициализируем хранилище с криптосистемой
    let storage = PasswordStorage::new(crypto);

        loop {
        println!("\nВыберите действие:");
        println!("1. Добавить пароль");
        println!("2. Показать сохраненные пароли");
        println!("3. Выход");
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => {
                println!("Введите пароль для сохранения:");
                let mut password = String::new();
                io::stdin().read_line(&mut password)?;
                let password = password.trim();
                
                match PasswordValidator::validate(password) {
                    Ok(_) => {
                        storage.save(password, "passwords.enc")?;
                        println!("✅ Пароль зашифрован и сохранен");
                    },
                    Err(e) => eprintln!("❌ Ошибка: {}", e),
                }
            },
            "2" => {
                match storage.load("passwords.enc") {
                    Ok(passwords) => {
                        println!("🔐 Сохраненные пароли:");
                        for (i, pass) in passwords.iter().enumerate() {
                            println!("{}. {}", i+1, pass);
                        }
                    },
                    Err(e) => eprintln!("❌ Ошибка загрузки: {}", e),
                }
            },
            "3" => break,
            _ => println!("Неверный выбор"),
        }
    }

    Ok(())
}