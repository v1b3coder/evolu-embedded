//! Cryptographic primitives for Evolu.
//!
//! Port of `packages/common/src/Crypto.ts`.

use crate::types::Fingerprint;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;

/// SLIP-21 hierarchical deterministic key derivation.
///
/// <https://github.com/satoshilabs/slips/blob/master/slip-0021.md>
///
/// Returns the right half (bytes 32..64) of the final HMAC-SHA512 node.
pub fn slip21_derive(seed: &[u8], path: &[&str]) -> [u8; 32] {
    // Master node: HMAC-SHA512(key="Symmetric key seed", data=seed)
    let mut mac =
        HmacSha512::new_from_slice(b"Symmetric key seed").expect("HMAC accepts any key size");
    mac.update(seed);
    let master = mac.finalize().into_bytes();

    let mut current_node = [0u8; 64];
    current_node.copy_from_slice(&master);

    // Derive each path element
    for label in path {
        current_node = derive_slip21_node(label, &current_node);
    }

    // Return right half (bytes 32..64)
    let mut result = [0u8; 32];
    result.copy_from_slice(&current_node[32..64]);
    result
}

/// Derive a single SLIP-21 child node.
///
/// message = 0x00 || UTF-8(label)
/// child = HMAC-SHA512(key=parent[0..32], data=message)
fn derive_slip21_node(label: &str, parent: &[u8; 64]) -> [u8; 64] {
    let key = &parent[0..32];
    let label_bytes = label.as_bytes();

    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&[0x00]); // null byte prefix
    mac.update(label_bytes);
    let result = mac.finalize().into_bytes();

    let mut node = [0u8; 64];
    node.copy_from_slice(&result);
    node
}

/// PADMÉ padded length — obscures plaintext length.
///
/// Based on PURB paper: <https://bford.info/pub/sec/purb.pdf>
pub fn padme_padded_length(length: u32) -> u32 {
    if length == 0 {
        return 0;
    }
    let e = 31 - (length.leading_zeros() as i32);
    let s = if e == 0 {
        0
    } else {
        32 - ((e as u32).leading_zeros() as i32)
    };
    let z = core::cmp::max(0, e - s);
    let mask = (1u32 << z) - 1;
    (length + mask) & !mask
}

/// Returns the number of padding bytes needed.
pub fn padme_padding_size(length: u32) -> u32 {
    padme_padded_length(length) - length
}

/// Compute a 12-byte fingerprint from a 16-byte TimestampBytes.
///
/// fingerprint = SHA-256(timestamp)[0..12]
pub fn timestamp_to_fingerprint(ts_bytes: &[u8; 16]) -> Fingerprint {
    let hash = Sha256::digest(ts_bytes);
    let mut fp = [0u8; 12];
    fp.copy_from_slice(&hash[..12]);
    fp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slip21_known_vector() {
        // Mnemonic "all all all all all all all all all all all all"
        // In the TS test, mnemonicToOwnerSecret converts this to a 32-byte entropy.
        // BIP-39: "all" repeated 12 times with English wordlist.
        // The word "all" is at index 44 in BIP-39 English wordlist.
        // 12 words × 11 bits = 132 bits = 128 bits entropy + 4 bits checksum.
        // Entropy for "all" × 12: each word is index 44 = 0b00000101100
        // 44 in 11 bits = 00000101100
        // 12 words: 00000101100 repeated 12 times = 132 bits
        // First 128 bits (16 bytes) = entropy, last 4 bits = checksum
        // 00000101100 00000101100 00000101100 00000101100
        // 00000101100 00000101100 00000101100 00000101100
        // 00000101100 00000101100 00000101100 00000101100
        //
        // As bits: 0000010110000000101100000001011000000010110
        //          0000010110000000101100000001011000000010110
        //          0000010110000000101100000001011000000010110
        //
        // 16 bytes hex: 02c02c02c02c02c02c02c02c02c02c02
        // But TS uses mnemonicToEntropy which returns 16 bytes (128 bits).
        // Let's use the known hex output directly.
        //
        // From the TS test: the OwnerSecret for "all all all..." mnemonic.
        // We know the SLIP-21 outputs. Let's verify with the raw seed.
        //
        // Actually, BIP-39 mnemonicToEntropy("all all all all all all all all all all all all")
        // yields specific 16 bytes. The TS code uses @scure/bip39 mnemonicToEntropy.
        //
        // Word "all" = index 44 in BIP39 English wordlist
        // Binary: 00000101100 (11 bits) × 12 = 132 bits
        // Entropy (first 128 bits / 16 bytes):
        // 00000101 10000000 10110000 00010110 00000010 11000000 01011000 00010110
        // 00000010 11000000 01011000 00010110 00000010 11000000 01011000 00010110
        // Hex: 05 80 B0 16 02 C0 58 16 02 C0 58 16 02 C0 58 16
        // But we need 32 bytes (OwnerSecret). The TS uses mnemonicToEntropy which
        // for a 12-word mnemonic returns 16 bytes. Then createOwnerSecret pads or
        // the function signature accepts Entropy16.
        //
        // Looking at Owner.ts: mnemonicToOwnerSecret calls bip39.mnemonicToEntropy
        // which returns Uint8Array. For 12 words = 16 bytes entropy.
        // Then it's cast to OwnerSecret which is Entropy32... but wait, 12 words
        // give 16 bytes, not 32. Let me check.
        //
        // Actually from Owner.ts: OwnerSecret = Entropy32, and the function is:
        // mnemonicToOwnerSecret(m) = bip39.mnemonicToEntropy(m, wordlist) as OwnerSecret
        // But bip39 12-word mnemonic gives 16 bytes...
        //
        // The SLIP-21 function accepts Entropy16 | Entropy32 | Entropy64.
        // So for 12-word mnemonic, seed is 16 bytes.

        // BIP-39 entropy for "all all all all all all all all all all all all"
        let seed: [u8; 16] = [
            0x06, 0x60, 0xCC, 0x19, 0x83, 0x30, 0x66, 0x0C, 0xC1, 0x98, 0x33, 0x06, 0x60, 0xCC,
            0x19, 0x83,
        ];

        let owner_id = slip21_derive(&seed, &["Evolu", "Owner Id"]);
        assert_eq!(
            hex(&owner_id),
            "bce9b26dad1a3364c105eb65e7aef032fdffd53816819ac4664442c4a915327f"
        );

        let encryption_key = slip21_derive(&seed, &["Evolu", "Encryption Key"]);
        assert_eq!(
            hex(&encryption_key),
            "abf2095887bc74adda889a572e29a407a457a39bfdd4202d34ee6eac5c28effc"
        );
    }

    #[test]
    fn padme_test_vectors() {
        let cases: &[(u32, u32)] = &[
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 4),
            (8, 8),
            (9, 10),
            (15, 16),
            (16, 16),
            (17, 18),
            (31, 32),
            (32, 32),
            (33, 36),
            (64, 64),
            (65, 72),
            (100, 104),
            (128, 128),
            (129, 144),
            (200, 208),
            (256, 256),
            (300, 304),
            (512, 512),
            (1000, 1024),
            (1024, 1024),
            (2048, 2048),
            (4096, 4096),
            (10000, 10240),
            (65536, 65536),
            (100000, 100352),
            (1048576, 1048576),
        ];

        for &(input, expected) in cases {
            assert_eq!(
                padme_padded_length(input),
                expected,
                "PADME({}) should be {}",
                input,
                expected
            );
            assert_eq!(
                padme_padding_size(input),
                expected - input,
                "PADME padding for {} should be {}",
                input,
                expected - input
            );
        }
    }

    #[test]
    fn fingerprint_from_timestamp() {
        let ts = [0u8; 16];
        let fp = timestamp_to_fingerprint(&ts);
        // SHA-256 of 16 zero bytes, first 12 bytes
        let full_hash = Sha256::digest(&ts);
        assert_eq!(&fp, &full_hash[..12]);
        assert_eq!(fp.len(), 12);
    }

    /// Helper to convert bytes to hex string for test assertions.
    fn hex(bytes: &[u8]) -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{:02x}", b)).collect()
    }

    extern crate alloc;
}
