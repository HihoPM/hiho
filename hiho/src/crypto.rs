use aes::Aes256;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use cipher::{
    BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray,
    KeyInit,
};
use std::io;

pub struct Crypto {
    key: GenericArray<u8, typenum::U32>,
    iv: GenericArray<u8, typenum::U16>,
}

impl Crypto {
    pub fn new(password: &str) -> Result<Self, io::Error> {
        let salt = b"your_fixed_salt";
        let mut derived_key = [0u8; 32];

        // Создаём HMAC-SHA256 вручную
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(password.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Ошибка инициализации HMAC"))?;

        // Применяем PBKDF2
        pbkdf2(&mut mac, salt, 65536, &mut derived_key);

        let key = GenericArray::from_slice(&derived_key).clone();
        let iv = Self::generate_iv();

        Ok(Self { key, iv })
    }

    fn generate_iv() -> GenericArray<u8, typenum::U16> {
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        GenericArray::from(iv)
    }

    pub fn encrypt(&self, data: &str) -> Vec<u8> {
        let cipher = Aes256::new(&self.key);
        let mut buffer = data.as_bytes().to_vec();

        let pos = buffer.len();
        let block_size = 16;
        let padding_len = block_size - (pos % block_size);
        buffer.resize(pos + padding_len, padding_len as u8);

        let mut encrypted = vec![0u8; buffer.len()];
        for (i, chunk) in buffer.chunks(block_size).enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);

            if i == 0 {
                for j in 0..block_size {
                    block[j] ^= self.iv[j];
                }
            } else {
                for j in 0..block_size {
                    block[j] ^= encrypted[(i - 1) * block_size + j];
                }
            }

            cipher.encrypt_block(&mut block);
            encrypted[i*block_size..(i+1)*block_size].copy_from_slice(&block);
        }

        encrypted
    }

    pub fn decrypt(&self, data: &[u8]) -> String {
        let cipher = Aes256::new(&self.key);
        let mut decrypted = vec![0u8; data.len()];

        for (i, chunk) in data.chunks(16).enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);

            if i == 0 {
                for j in 0..16 {
                    block[j] ^= self.iv[j];
                }
            } else {
                for j in 0..16 {
                    block[j] ^= data[(i - 1) * 16 + j];
                }
            }

            decrypted[i*16..(i+1)*16].copy_from_slice(&block);
        }

        let padding_len = *decrypted.last().unwrap() as usize;
        let result = String::from_utf8(decrypted[..decrypted.len() - padding_len].to_vec()).unwrap();
        result
    }

    pub fn get_key_hex(&self) -> String {
        hex::encode(self.key.as_slice())
    }

    pub fn get_iv_hex(&self) -> String {
        hex::encode(self.iv.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_pbkdf2_key_derivation() -> io::Result<()> {
        let password = "masterpass123";
        let crypto = Crypto::new(password)?;
        assert_eq!(crypto.get_key_hex().len(), 64); // 32 bytes in hex
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() -> io::Result<()> {
        let password = "masterpass123";
        let crypto = Crypto::new(password)?;

        let original = "mysecretpassword";
        let encrypted = crypto.encrypt(original);
        let decrypted = crypto.decrypt(&encrypted);

        assert_eq!(original, decrypted);
        Ok(())
    }

    #[test]
    fn test_multiple_keys_from_same_password() -> io::Result<()> {
        let password = "samepassword";
        let crypto1 = Crypto::new(password)?;
        let crypto2 = Crypto::new(password)?;

        assert_eq!(crypto1.get_key_hex(), crypto2.get_key_hex());
        assert_ne!(crypto1.get_iv_hex(), crypto2.get_iv_hex()); // IV должен быть разным

        Ok(())
    }

    #[test]
    fn test_invalid_password_produces_different_key() -> io::Result<()> {
        let password1 = "password123";
        let password2 = "password456";

        let crypto1 = Crypto::new(password1)?;
        let crypto2 = Crypto::new(password2)?;

        assert_ne!(crypto1.get_key_hex(), crypto2.get_key_hex());
        Ok(())
    }
}