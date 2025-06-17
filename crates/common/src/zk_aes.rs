// In tlsn/crates/common/src/zk_aes.rs

use mpz_memory_core::binary::U8;
use mpz_memory_core::{binary::Binary, Array, Vector};
use mpz_vm_core::{prelude::*, Vm};

/// No-op AES-CTR "encryption" that doesn't actually do anything.
pub struct AesCtr {
    // Keep some fields to maintain API compatibility
    key: Option<[u8; 16]>,
    iv: Option<[u8; 8]>,
    counter: u64,
}

impl AesCtr {
    /// Creates a new dummy AES-CTR cipher that doesn't actually do any encryption.
    pub fn new(key: &[u8; 16], nonce: &[u8; 8], counter: u64) -> Self {
        Self {
            key: Some(*key),
            iv: Some(*nonce),
            counter,
        }
    }

    /// No-op version that doesn't actually encrypt/decrypt.
    pub fn apply_keystream(&mut self, _data: &mut [u8]) {
        // Do nothing - data remains unchanged
    }

    /// No-op version that simply returns the input data.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Just return a copy of the plaintext
        plaintext.to_vec()
    }

    /// Maintain API compatibility
    pub fn decode_key(&mut self, _vm: &mut dyn Vm<Binary>) -> Result<(), AesCtrError> {
        // No-op
        Ok(())
    }

    /// Maintain API compatibility
    pub fn finish_decode(&mut self) -> Result<(), AesCtrError> {
        // No-op
        Ok(())
    }

    /// Factory method for MPC-TLS compatibility
    pub fn for_mpc(key: Option<Array<U8, 16>>, iv: Option<Array<U8, 4>>) -> Self {
        let key = [0u8; 16]; // Default key
        let nonce = [0u8; 8]; // Default nonce
        let counter = 0; // Default counter

        Self::new(&key, &nonce, counter)
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
