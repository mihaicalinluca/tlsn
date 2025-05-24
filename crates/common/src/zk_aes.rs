use aes::cipher::KeyIvInit;
use aes::Aes128;
use ctr::cipher::{generic_array::GenericArray, StreamCipher};
use ctr::{Ctr128BE, Ctr64BE};

type Aes128Ctr64 = Ctr128BE<Aes128>;

/// Standard AES-CTR encryption (no zero-knowledge).
pub struct AesCtr {
    cipher: Aes128Ctr64,
}

impl AesCtr {
    /// Creates a new AES-CTR cipher with a 128-bit key and 64-bit IV + 64-bit counter.
    pub fn new(key: &[u8; 16], nonce: &[u8; 8], counter: u64) -> Self {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(nonce);
        iv[8..].copy_from_slice(&counter.to_be_bytes());

        let cipher = Aes128Ctr64::new(key.into(), &iv.into());
        Self { cipher }
    }

    /// Encrypts or decrypts data in-place.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    /// Encypts and returns the encrypted data.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        self.cipher.apply_keystream(&mut ciphertext);
        ciphertext
    }
}

/// Error for AesCtr
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub enum AesCtrError {
    #[error("ciphertext is missing")]
    /// The ciphertext is missing
    MissingCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ctr_encrypt_decrypt() {
        let key = [0x00; 16];
        let nonce = [0x01; 8];
        let counter = 2;
        let mut plaintext = b"Hello, AES-CTR mode!".to_vec();

        let mut encryptor = AesCtr::new(&key, &nonce, counter);
        encryptor.apply_keystream(&mut plaintext);
        let ciphertext = plaintext.clone();

        let mut decryptor = AesCtr::new(&key, &nonce, counter);
        decryptor.apply_keystream(&mut plaintext);

        assert_eq!(plaintext, b"Hello, AES-CTR mode!");
        assert_ne!(ciphertext, plaintext);
    }
}
