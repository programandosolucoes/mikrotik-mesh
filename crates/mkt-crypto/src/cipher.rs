use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use crate::error::CryptoError;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Authenticated encryption layer for tunnel frames using ChaCha20-Poly1305 (IETF RFC 8439)
#[derive(Clone)]
pub struct TunnelCipher {
    key: [u8; 32],
}

impl TunnelCipher {
    /// Create cipher from a 32-byte key
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive a 256-bit symmetric key from a pre-shared secret string using SHA-256
    pub fn from_secret(secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"mkt-tunnel-aead-v1:");
        hasher.update(secret.as_bytes());
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Self { key }
    }

    /// Encrypts plaintext using ChaCha20-Poly1305.
    /// Wire format: [12-byte Nonce] + [Ciphertext + 16-byte Poly1305 MAC Tag]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("{}", e)))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts and authenticates ciphertext using ChaCha20-Poly1305.
    /// Returns the authenticated plaintext, or AuthenticationFailed if tampered or wrong key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::InvalidBufferLength {
                required: NONCE_LEN + TAG_LEN,
                available: ciphertext.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = Nonce::from_slice(&ciphertext[..NONCE_LEN]);
        let encrypted_payload = &ciphertext[NONCE_LEN..];

        let plaintext = cipher
            .decrypt(nonce, encrypted_payload)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_cipher_roundtrip() {
        let cipher = TunnelCipher::from_secret("SuperSecretPSK_2026!");
        let message = b"Hello, MikroTik EoIP Encrypted Mesh Network!";

        let encrypted = cipher.encrypt(message).expect("encryption should succeed");
        assert_ne!(&encrypted[NONCE_LEN..], message);
        assert_eq!(encrypted.len(), NONCE_LEN + message.len() + TAG_LEN);

        let decrypted = cipher.decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(&decrypted, message);
    }

    #[test]
    fn test_tunnel_cipher_tamper_detection() {
        let cipher = TunnelCipher::from_secret("KeyA");
        let message = b"Confidential ethernet frame payload";
        let mut encrypted = cipher.encrypt(message).unwrap();

        // Tamper with one bit of ciphertext
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01;

        let result = cipher.decrypt(&encrypted);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_tunnel_cipher_wrong_key_rejected() {
        let cipher_a = TunnelCipher::from_secret("KeyA");
        let cipher_b = TunnelCipher::from_secret("KeyB");

        let message = b"Secret L2 frame";
        let encrypted = cipher_a.encrypt(message).unwrap();

        let result = cipher_b.decrypt(&encrypted);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }
}
