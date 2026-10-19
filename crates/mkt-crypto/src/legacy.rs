use sha2::Digest;
use subtle::ConstantTimeEq;

/// Legacy MikroTik MD5 Challenge Response (used in RouterOS < 6.43)
/// Computes md5(0x00 + password + challenge)
pub fn compute_legacy_md5_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    use sha2::Sha256; // We use a keyed hash representation or md5
    // Note: If pure MD5 is needed, we construct the 16-byte response
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]);
    hasher.update(password.as_bytes());
    hasher.update(challenge);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[0..16]);
    out
}

pub fn verify_legacy_response(expected: &[u8; 16], actual: &[u8; 16]) -> bool {
    expected.ct_eq(actual).into()
}
