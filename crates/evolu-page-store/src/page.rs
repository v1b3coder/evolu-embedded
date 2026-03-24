//! Encrypted page format with AEAD + AAD for replay/swap protection.
//!
//! Each page stored on the untrusted host is encrypted with XChaCha20-Poly1305.
//! The Associated Authenticated Data (AAD) binds each ciphertext to its
//! page_id and sequence number, preventing the host from:
//! - Swapping pages between slots (AAD includes page_id)
//! - Replaying old versions of a page (AAD includes sequence)
//! - Tampering with any byte (AEAD authentication)
//!
//! Wire format: nonce(24B) + ciphertext(plaintext_len) + tag(16B)

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};

/// Overhead added by encryption: 24 bytes nonce + 16 bytes Poly1305 tag.
pub const ENCRYPTION_OVERHEAD: usize = 24 + 16;

/// Maximum plaintext that fits in a page.
pub const MAX_PLAINTEXT: usize = 2048;

/// Maximum encrypted page size on wire.
pub const MAX_ENCRYPTED_SIZE: usize = MAX_PLAINTEXT + ENCRYPTION_OVERHEAD;

/// Build the AAD bytes from page_id and sequence.
///
/// AAD = page_id(4 bytes LE) || sequence(8 bytes LE) = 12 bytes total.
fn build_aad(page_id: u32, sequence: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[0..4].copy_from_slice(&page_id.to_le_bytes());
    aad[4..12].copy_from_slice(&sequence.to_le_bytes());
    aad
}

/// Encrypt a plaintext page in-place.
///
/// - `key`: 32-byte device key (never leaves the chip)
/// - `nonce`: 24-byte random nonce (caller must generate via `fill_random`)
/// - `plaintext`: page data, up to `MAX_PLAINTEXT` bytes
/// - `page_id`: identifies which page slot this belongs to
/// - `sequence`: monotonic counter preventing replay
/// - `output`: buffer for encrypted output, must be >= plaintext.len() + ENCRYPTION_OVERHEAD
///
/// Returns the number of bytes written to `output`.
pub fn encrypt_page(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    page_id: u32,
    sequence: u64,
    output: &mut [u8],
) -> Result<usize, PageCryptoError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(PageCryptoError::PlaintextTooLarge);
    }

    let total = plaintext.len() + ENCRYPTION_OVERHEAD;
    if output.len() < total {
        return Err(PageCryptoError::OutputBufferTooSmall);
    }

    let aad = build_aad(page_id, sequence);
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    // Write nonce
    output[..24].copy_from_slice(nonce);

    // Copy plaintext into output buffer after nonce, encrypt in-place
    let ct_start = 24;
    let ct_end = ct_start + plaintext.len();
    output[ct_start..ct_end].copy_from_slice(plaintext);

    let tag = cipher
        .encrypt_in_place_detached(xnonce, &aad, &mut output[ct_start..ct_end])
        .map_err(|_| PageCryptoError::EncryptFailed)?;

    // Append tag
    output[ct_end..ct_end + 16].copy_from_slice(&tag);

    Ok(total)
}

/// Decrypt an encrypted page.
///
/// - `key`: 32-byte device key
/// - `encrypted`: wire data (nonce(24) + ciphertext(N) + tag(16))
/// - `page_id`: expected page ID (must match what was used during encryption)
/// - `sequence`: expected sequence (must match what was used during encryption)
/// - `output`: buffer for decrypted plaintext
///
/// Returns the number of plaintext bytes written to `output`.
/// Fails if the host tampered with data, swapped pages, or replayed old versions.
pub fn decrypt_page(
    key: &[u8; 32],
    encrypted: &[u8],
    page_id: u32,
    sequence: u64,
    output: &mut [u8],
) -> Result<usize, PageCryptoError> {
    if encrypted.len() < ENCRYPTION_OVERHEAD {
        return Err(PageCryptoError::DataTooShort);
    }

    let nonce = XNonce::from_slice(&encrypted[..24]);
    let ct_and_tag = &encrypted[24..];
    let plaintext_len = ct_and_tag.len() - 16;

    if output.len() < plaintext_len {
        return Err(PageCryptoError::OutputBufferTooSmall);
    }

    let aad = build_aad(page_id, sequence);
    let cipher = XChaCha20Poly1305::new(key.into());

    // Copy ciphertext (without tag) into output, then decrypt in-place
    output[..plaintext_len].copy_from_slice(&ct_and_tag[..plaintext_len]);
    let tag = Tag::from_slice(&ct_and_tag[plaintext_len..]);

    cipher
        .decrypt_in_place_detached(nonce, &aad, &mut output[..plaintext_len], tag)
        .map_err(|_| PageCryptoError::DecryptFailed)?;

    Ok(plaintext_len)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageCryptoError {
    PlaintextTooLarge,
    OutputBufferTooSmall,
    DataTooShort,
    EncryptFailed,
    /// Decryption failed: data was tampered, page was swapped, or replayed.
    DecryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    fn random_nonce() -> [u8; 24] {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).unwrap();
        nonce
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let nonce = random_nonce();
        let plaintext = b"Hello, encrypted page!";

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, plaintext, 42, 1, &mut encrypted).unwrap();

        let mut decrypted = [0u8; MAX_PLAINTEXT];
        let dec_len = decrypt_page(&key, &encrypted[..enc_len], 42, 1, &mut decrypted).unwrap();
        assert_eq!(&decrypted[..dec_len], plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = random_nonce();
        let plaintext = b"sensitive data";

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, plaintext, 0, 1, &mut encrypted).unwrap();
        encrypted[30] ^= 0xFF;

        let mut decrypted = [0u8; MAX_PLAINTEXT];
        assert_eq!(
            decrypt_page(&key, &encrypted[..enc_len], 0, 1, &mut decrypted),
            Err(PageCryptoError::DecryptFailed)
        );
    }

    #[test]
    fn wrong_page_id_fails() {
        let key = test_key();
        let nonce = random_nonce();

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, b"data", 5, 1, &mut encrypted).unwrap();

        let mut decrypted = [0u8; MAX_PLAINTEXT];
        assert_eq!(
            decrypt_page(&key, &encrypted[..enc_len], 6, 1, &mut decrypted),
            Err(PageCryptoError::DecryptFailed)
        );
    }

    #[test]
    fn wrong_sequence_fails() {
        let key = test_key();
        let nonce = random_nonce();

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, b"data", 0, 1, &mut encrypted).unwrap();

        let mut decrypted = [0u8; MAX_PLAINTEXT];
        assert_eq!(
            decrypt_page(&key, &encrypted[..enc_len], 0, 2, &mut decrypted),
            Err(PageCryptoError::DecryptFailed)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let nonce = random_nonce();

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, b"secret", 0, 1, &mut encrypted).unwrap();

        let wrong_key = [0xFF; 32];
        let mut decrypted = [0u8; MAX_PLAINTEXT];
        assert_eq!(
            decrypt_page(&wrong_key, &encrypted[..enc_len], 0, 1, &mut decrypted),
            Err(PageCryptoError::DecryptFailed)
        );
    }

    #[test]
    fn empty_plaintext() {
        let key = test_key();
        let nonce = random_nonce();

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, &[], 0, 0, &mut encrypted).unwrap();
        assert_eq!(enc_len, ENCRYPTION_OVERHEAD);

        let mut decrypted = [0u8; MAX_PLAINTEXT];
        let dec_len = decrypt_page(&key, &encrypted[..enc_len], 0, 0, &mut decrypted).unwrap();
        assert_eq!(dec_len, 0);
    }

    #[test]
    fn full_page() {
        let key = test_key();
        let nonce = random_nonce();
        let plaintext: Vec<u8> = (0..MAX_PLAINTEXT).map(|i| (i % 256) as u8).collect();

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &nonce, &plaintext, 0, 0, &mut encrypted).unwrap();
        assert_eq!(enc_len, MAX_ENCRYPTED_SIZE);

        let mut decrypted = [0u8; MAX_PLAINTEXT];
        let dec_len = decrypt_page(&key, &encrypted[..enc_len], 0, 0, &mut decrypted).unwrap();
        assert_eq!(dec_len, MAX_PLAINTEXT);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn different_nonces_different_ciphertext() {
        let key = test_key();
        let plaintext = b"same data";

        let mut enc1 = [0u8; MAX_ENCRYPTED_SIZE];
        let mut enc2 = [0u8; MAX_ENCRYPTED_SIZE];

        let len1 = encrypt_page(&key, &random_nonce(), plaintext, 0, 1, &mut enc1).unwrap();
        let len2 = encrypt_page(&key, &random_nonce(), plaintext, 0, 1, &mut enc2).unwrap();

        assert_eq!(len1, len2);
        assert_ne!(&enc1[24..len1], &enc2[24..len2]);

        let mut dec1 = [0u8; MAX_PLAINTEXT];
        let mut dec2 = [0u8; MAX_PLAINTEXT];
        decrypt_page(&key, &enc1[..len1], 0, 1, &mut dec1).unwrap();
        decrypt_page(&key, &enc2[..len2], 0, 1, &mut dec2).unwrap();
        assert_eq!(&dec1[..plaintext.len()], plaintext);
        assert_eq!(&dec2[..plaintext.len()], plaintext);
    }

    #[test]
    fn host_sees_only_opaque_data() {
        let key = test_key();
        let plaintext = b"table=todo, id=abc, title=Buy milk";

        let mut encrypted = [0u8; MAX_ENCRYPTED_SIZE];
        let enc_len = encrypt_page(&key, &random_nonce(), plaintext, 0, 1, &mut encrypted).unwrap();

        let data = &encrypted[..enc_len];
        assert!(
            !data.windows(plaintext.len()).any(|w| w == plaintext),
            "Plaintext found in encrypted output!"
        );
    }
}
