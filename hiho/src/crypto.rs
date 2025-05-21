use aes::Aes256;
use rand::RngCore;
use hex;
use cipher::{
    BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray,
    KeyInit,
};

pub struct Crypto {
    key: GenericArray<u8, typenum::U32>,
    iv: GenericArray<u8, typenum::U16>,
}

impl Crypto {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut iv);
        
        Self {
            key: GenericArray::from(key),
            iv: GenericArray::from(iv),
        }
    }

    pub fn encrypt(&self, data: &str) -> Vec<u8> {
    let cipher = Aes256::new(&self.key);
    let mut buffer = data.as_bytes().to_vec();
    
    // Добавляем padding
    let pos = buffer.len();
    let block_size = 16;
    let padding_len = block_size - (pos % block_size);
    buffer.resize(pos + padding_len, padding_len as u8);
    
    // Шифруем с CBC
    let mut encrypted = vec![0u8; buffer.len()];
    for (i, chunk) in buffer.chunks(block_size).enumerate() {
        let mut block = GenericArray::clone_from_slice(chunk);
        
        // XOR с IV (для первого блока) или предыдущим зашифрованным блоком
        if i == 0 {
            for j in 0..block_size {
                block[j] ^= self.iv[j];
            }
        } else {
            for j in 0..block_size {
                block[j] ^= encrypted[(i-1)*block_size + j];
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
        
        // Дешифруем
        let block_size = 16;
        for (i, chunk) in data.chunks(block_size).enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            
            if i == 0 {
                // Первый блок XOR с IV
                for (j, byte) in block.iter_mut().enumerate() {
                    *byte ^= self.iv[j];
                }
            } else {
                // Остальные блоки XOR с предыдущим зашифрованным блоком
                for (j, byte) in block.iter_mut().enumerate() {
                    *byte ^= data[(i-1)*block_size + j];
                }
            }
            decrypted[i*block_size..(i+1)*block_size].copy_from_slice(&block);
        }
        
        // Удаляем padding
        let padding_len = *decrypted.last().unwrap() as usize;
        decrypted.truncate(decrypted.len() - padding_len);
        
        String::from_utf8(decrypted).unwrap()
    }

    pub fn get_key_hex(&self) -> String {
        hex::encode(self.key.as_slice())
    }

    pub fn get_iv_hex(&self) -> String {
        hex::encode(self.iv.as_slice())
    }
}