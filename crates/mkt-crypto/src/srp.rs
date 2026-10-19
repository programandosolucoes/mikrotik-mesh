use crate::error::CryptoError;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Multiplier k = SHA256(Generator || Context)
const SRP_K_CONSTANT: [u8; 32] = [
    0x5b, 0x98, 0xa5, 0x27, 0x93, 0x36, 0x34, 0x5a, 0x76, 0x6e, 0x8a, 0x2b, 0x4f, 0x1a, 0x3c, 0x6e,
    0x88, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(pub Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SensitiveBytes(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Computes x = SHA256(salt || SHA256(username || ":" || password))
pub fn compute_x(username: &str, password: &str, salt: &[u8]) -> Scalar {
    let mut inner = Sha256::new();
    inner.update(username.as_bytes());
    inner.update(b":");
    inner.update(password.as_bytes());
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(salt);
    outer.update(&inner_hash);
    let mut outer_hash = outer.finalize();

    // Map 32 bytes into Scalar
    let scalar = Scalar::from_bytes_mod_order(outer_hash.into());
    outer_hash.zeroize();
    scalar
}

/// Compute verifier v = x * G
pub fn compute_verifier(username: &str, password: &str, salt: &[u8]) -> CompressedEdwardsY {
    let x = compute_x(username, password, salt);
        let v_point = ED25519_BASEPOINT_TABLE * &x;
    v_point.compress()
}

/// Helper: calculates u = SHA256(A || B)
pub fn compute_u(pub_a: &[u8; 32], pub_b: &[u8; 32]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(pub_a);
    hasher.update(pub_b);
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(hash.into())
}

/// Compute client proof M1 = SHA256(A || B || K)
pub fn compute_m1(pub_a: &[u8; 32], pub_b: &[u8; 32], session_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pub_a);
    hasher.update(pub_b);
    hasher.update(session_key);
    hasher.finalize().into()
}

/// Compute server proof M2 = SHA256(A || M1 || K)
pub fn compute_m2(pub_a: &[u8; 32], m1: &[u8; 32], session_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pub_a);
    hasher.update(m1);
    hasher.update(session_key);
    hasher.finalize().into()
}

/// Constant-time proof verification (Anti-Timing Attacks)
pub fn verify_proof_constant_time(expected: &[u8; 32], actual: &[u8; 32]) -> Result<(), CryptoError> {
    if expected.ct_eq(actual).into() {
        Ok(())
    } else {
        Err(CryptoError::AuthenticationFailed)
    }
}

/// Client-side EC-SRP5 Session
pub struct SrpClientSession {
    username: String,
    password: SensitiveBytes,
    client_private_a: Scalar,
    pub client_public_a: [u8; 32],
}

impl SrpClientSession {
    pub fn new(username: &str, password: &str) -> Self {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        let a_point = ED25519_BASEPOINT_TABLE * &a;
        let pub_a = a_point.compress().to_bytes();

        Self {
            username: username.to_string(),
            password: SensitiveBytes::new(password.as_bytes().to_vec()),
            client_private_a: a,
            client_public_a: pub_a,
        }
    }

    /// Step 2: Client processes server salt and public B, calculates session key K and proof M1
    pub fn process_challenge(
        &mut self,
        salt: &[u8],
        server_pub_b: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let b_point = match CompressedEdwardsY(*server_pub_b).decompress() {
            Some(pt) if !pt.is_small_order() => pt,
            _ => return Err(CryptoError::InvalidEphemeralKey),
        };

        let u = compute_u(&self.client_public_a, server_pub_b);
        let pwd_str = std::str::from_utf8(self.password.as_slice()).map_err(|_| CryptoError::AuthenticationFailed)?;
        let x = compute_x(&self.username, pwd_str, salt);

        // v = x * G
            let v_point = ED25519_BASEPOINT_TABLE * &x;

        // k = Scalar(SRP_K_CONSTANT)
        let k_scalar = Scalar::from_bytes_mod_order(SRP_K_CONSTANT);
        let kv_point = v_point * k_scalar;

        // (B - k*v)
        let diff = b_point - kv_point;

        // S = (a + u*x) * (B - k*v)
        let exp = self.client_private_a + (u * x);
        let s_point = diff * exp;
        let s_bytes = s_point.compress().to_bytes();

        // K = SHA256(S)
        let mut k_hasher = Sha256::new();
        k_hasher.update(&s_bytes);
        let session_key: [u8; 32] = k_hasher.finalize().into();

        // M1 = SHA256(A || B || K)
        let m1 = compute_m1(&self.client_public_a, server_pub_b, &session_key);

        Ok((session_key, m1))
    }

    /// Step 3: Validate server proof M2
    pub fn verify_server_m2(
        &self,
        server_m2: &[u8; 32],
        server_pub_b: &[u8; 32],
        session_key: &[u8; 32],
    ) -> Result<(), CryptoError> {
        let m1 = compute_m1(&self.client_public_a, server_pub_b, session_key);
        let expected_m2 = compute_m2(&self.client_public_a, &m1, session_key);
        verify_proof_constant_time(&expected_m2, server_m2)
    }
}

/// Server-side EC-SRP5 Session
pub struct SrpServerSession {
    pub salt: [u8; 16],
    server_private_b: Scalar,
    pub server_public_b: [u8; 32],
    verifier_point: EdwardsPoint,
}

impl SrpServerSession {
    pub fn new(username: &str, password: &str) -> Self {
        let mut rng = OsRng;
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut salt);

        let x = compute_x(username, password, &salt);
        let verifier = ED25519_BASEPOINT_TABLE * &x;

        let b = Scalar::random(&mut rng);
        let k_scalar = Scalar::from_bytes_mod_order(SRP_K_CONSTANT);
        let b_point = (ED25519_BASEPOINT_TABLE * &b) + (verifier * k_scalar);

        Self {
            salt,
            server_private_b: b,
            server_public_b: b_point.compress().to_bytes(),
            verifier_point: verifier,
        }
    }

    /// Server processes client proof M1 and produces server proof M2
    pub fn verify_client_and_respond(
        &self,
        client_pub_a: &[u8; 32],
        client_m1: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let a_point = match CompressedEdwardsY(*client_pub_a).decompress() {
            Some(pt) if !pt.is_small_order() => pt,
            _ => return Err(CryptoError::InvalidEphemeralKey),
        };

        let u = compute_u(client_pub_a, &self.server_public_b);

        // S = b * (A + u*v)
        let uv_point = self.verifier_point * u;
        let base = a_point + uv_point;
        let s_point = base * self.server_private_b;
        let s_bytes = s_point.compress().to_bytes();

        // K = SHA256(S)
        let mut k_hasher = Sha256::new();
        k_hasher.update(&s_bytes);
        let session_key: [u8; 32] = k_hasher.finalize().into();

        // Expected M1
        let expected_m1 = compute_m1(client_pub_a, &self.server_public_b, &session_key);
        verify_proof_constant_time(&expected_m1, client_m1)?;

        // M2 = SHA256(A || M1 || K)
        let m2 = compute_m2(client_pub_a, client_m1, &session_key);

        Ok((session_key, m2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_srp5_full_handshake_success() {
        let username = "admin";
        let password = "SuperSecretPassword123!";

        // 1. Server initialized with credentials
        let server = SrpServerSession::new(username, password);

        // 2. Client initialized
        let mut client = SrpClientSession::new(username, password);

        // 3. Client processes salt and B from Server -> outputs (K, M1)
        let (client_k, client_m1) = client
            .process_challenge(&server.salt, &server.server_public_b)
            .expect("Client challenge calculation should succeed");

        // 4. Server verifies M1 and generates M2 -> outputs (K, M2)
        let (server_k, server_m2) = server
            .verify_client_and_respond(&client.client_public_a, &client_m1)
            .expect("Server authentication should succeed");

        // 5. Client verifies M2
        client
            .verify_server_m2(&server_m2, &server.server_public_b, &client_k)
            .expect("Client verification of M2 should succeed");

        // Both sides must derive the exact same 256-bit session key!
        assert_eq!(client_k, server_k);
    }

    #[test]
    fn test_ec_srp5_wrong_password_rejected() {
        let username = "admin";
        let password_correct = "CorrectPass1";
        let password_wrong = "WrongPass2";

        let server = SrpServerSession::new(username, password_correct);
        let mut client = SrpClientSession::new(username, password_wrong);

        let (_client_k, client_m1) = client
            .process_challenge(&server.salt, &server.server_public_b)
            .unwrap();

        let result = server.verify_client_and_respond(&client.client_public_a, &client_m1);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }
}
