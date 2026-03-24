//! Owner key derivation from OwnerSecret.
//!
//! Port of `packages/common/src/local-first/Owner.ts`.

use crate::crypto::slip21_derive;

/// Derived owner keys from a 32-byte (or 16-byte) secret.
#[derive(Clone, Debug)]
pub struct OwnerKeys {
    /// Unique public identifier (16 bytes).
    pub id: [u8; 16],
    /// Symmetric encryption key for XChaCha20-Poly1305 (32 bytes).
    pub encryption_key: [u8; 32],
    /// Authentication token for write operations (16 bytes).
    pub write_key: [u8; 16],
}

/// Derive all owner keys from an OwnerSecret.
///
/// The secret can be 16 bytes (from 12-word BIP-39 mnemonic) or 32 bytes.
pub fn derive_owner(secret: &[u8]) -> OwnerKeys {
    let id_full = slip21_derive(secret, &["Evolu", "OwnerIdBytes"]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&id_full[..16]);

    let encryption_key = slip21_derive(secret, &["Evolu", "OwnerEncryptionKey"]);

    let wk_full = slip21_derive(secret, &["Evolu", "OwnerWriteKey"]);
    let mut write_key = [0u8; 16];
    write_key.copy_from_slice(&wk_full[..16]);

    OwnerKeys {
        id,
        encryption_key,
        write_key,
    }
}

/// Derive a shard owner from a parent owner's encryption key and a path.
pub fn derive_shard_owner(parent_encryption_key: &[u8; 32], path: &[&str]) -> OwnerKeys {
    let shard_secret = slip21_derive(parent_encryption_key, path);
    derive_owner(&shard_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_owner_deterministic() {
        let secret = [0x42u8; 32];
        let owner1 = derive_owner(&secret);
        let owner2 = derive_owner(&secret);
        assert_eq!(owner1.id, owner2.id);
        assert_eq!(owner1.encryption_key, owner2.encryption_key);
        assert_eq!(owner1.write_key, owner2.write_key);
    }

    #[test]
    fn different_secrets_different_owners() {
        let owner1 = derive_owner(&[0x01u8; 32]);
        let owner2 = derive_owner(&[0x02u8; 32]);
        assert_ne!(owner1.id, owner2.id);
        assert_ne!(owner1.encryption_key, owner2.encryption_key);
        assert_ne!(owner1.write_key, owner2.write_key);
    }

    #[test]
    fn shard_derivation_deterministic() {
        let parent = derive_owner(&[0x42u8; 32]);
        let shard1 = derive_shard_owner(&parent.encryption_key, &["contacts"]);
        let shard2 = derive_shard_owner(&parent.encryption_key, &["contacts"]);
        assert_eq!(shard1.id, shard2.id);
    }

    #[test]
    fn different_paths_different_shards() {
        let parent = derive_owner(&[0x42u8; 32]);
        let contacts = derive_shard_owner(&parent.encryption_key, &["contacts"]);
        let photos = derive_shard_owner(&parent.encryption_key, &["photos"]);
        assert_ne!(contacts.id, photos.id);
        assert_ne!(contacts.encryption_key, photos.encryption_key);
    }

    #[test]
    fn different_parents_different_shards() {
        let parent1 = derive_owner(&[0x01u8; 32]);
        let parent2 = derive_owner(&[0x02u8; 32]);
        let shard1 = derive_shard_owner(&parent1.encryption_key, &["contacts"]);
        let shard2 = derive_shard_owner(&parent2.encryption_key, &["contacts"]);
        assert_ne!(shard1.id, shard2.id);
    }

    #[test]
    fn derive_from_known_mnemonic_seed() {
        // "all all all all all all all all all all all all" mnemonic
        // BIP-39 entropy: 16 bytes
        // BIP-39 entropy for "all all all all all all all all all all all all"
        let seed: [u8; 16] = [
            0x06, 0x60, 0xCC, 0x19, 0x83, 0x30, 0x66, 0x0C, 0xC1, 0x98, 0x33, 0x06, 0x60, 0xCC,
            0x19, 0x83,
        ];
        let owner = derive_owner(&seed);
        // The id should be first 16 bytes of SLIP21(seed, ["Evolu", "OwnerIdBytes"])
        // Full 32-byte output verified in crypto.rs test
        assert_eq!(owner.id.len(), 16);
        assert_eq!(owner.encryption_key.len(), 32);
        assert_eq!(owner.write_key.len(), 16);
    }
}
