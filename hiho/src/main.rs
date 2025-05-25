mod error;
mod password;
mod storage;
mod crypto;
mod credential;

use crate::crypto::Crypto;
use crate::error::PasswordError;
use crate::password::PasswordValidator;
use crate::storage::{PasswordStorage, Credential};
use crate::credential::Credential;
use std::io;

fn main() -> Result<(), PasswordError> {
    println!("🔒 Менеджер паролей v0.1");

    let mut master_password = String::new();
    io::stdin().read_line(&mut master_password)?;
    let master_password = master_password.trim();
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
        
        match Crypto::new(master_password) {
        Ok(crypto) => {
            let storage = PasswordStorage::new(crypto);

            loop {
                println!("\nВыберите действие:");
                println!("1. Добавить запись");
                println!("2. Показать записи");
                println!("3. Выход");

                let mut choice = String::new();
                io::stdin().read_line(&mut choice)?;

                match choice.trim() {
                    "1" => {
                        println!("Сайт:");
                        let mut site = String::new();
                        io::stdin().read_line(&mut site)?;
                        let site = site.trim();

                        println!("Логин:");
                        let mut login = String::new();
                        io::stdin().read_line(&mut login)?;
                        let login = login.trim();

                        println!("Пароль:");
                        let mut password = String::new();
                        io::stdin().read_line(&mut password)?;
                        let password = password.trim();

                        let credential = Credential::new(site, login, password);

                        storage.save(&[credential], "passwords.enc")?;
                        println!("✅ Запись добавлена");
                    },
                    "2" => {
                        match storage.load("passwords.enc") {
                            Ok(records) => {
                                println!("🔐 Сохраненные записи:");
                                for (i, record) in records.iter().enumerate() {
                                    println!(
                                        "{}. Сайт: {}, Логин: {}, Пароль: {}",
                                        i + 1,
                                        record.site,
                                        record.login,
                                        record.password
                                    );
                                }
                            },
                            Err(e) => eprintln!("❌ Ошибка загрузки: {}", e),
                        }
                    },
                    "3" => break,
                    _ => println!("Неверный выбор"),
                }
            }
        },
        Err(e) => return Err(PasswordError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e))),
    }
}

    Ok(())
}