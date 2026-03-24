//! Streaming encrypted timestamp index.
//!
//! The index is a sequential list of fixed-size entries, encrypted in chunks.
//! The device streams through it one chunk at a time — never holding the full
//! index in RAM.
//!
//! ## On-disk format
//!
//! ```text
//! header (36 bytes):
//!   sequence:      u64 LE      — replay protection (checked against on-chip state)
//!   nonce_seed:    [u8; 24]    — base nonce (chunk nonce = seed XOR chunk_index)
//!   total_entries: u32 LE      — truncation detection
//!
//! chunk 0:  ciphertext(entries[0..K]) || tag(16B)
//! chunk 1:  ciphertext(entries[K..2K]) || tag(16B)
//! ...
//! chunk N:  ciphertext(remaining entries) || tag(16B)
//!
//! Each chunk AAD = sequence(8B LE) || chunk_index(4B LE)
//! ```
//!
//! ## Entry format (30 bytes)
//!
//! ```text
//! timestamp:    [u8; 16]   — TimestampBytes (sorted key)
//! fingerprint:  [u8; 12]   — SHA-256(timestamp)[0..12] for RBSR sync
//! page_id:      u16 LE     — which data page holds this entry's DbChange
//! ```

use crate::host::HostInterface;
use crate::trusted_state::TrustedState;
use evolu_core::platform::Platform;
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use evolu_core::types::*;

/// Size of one index entry.
pub const INDEX_ENTRY_SIZE: usize = 30;

/// Number of entries per encrypted chunk.
pub const ENTRIES_PER_CHUNK: usize = 64;

/// Max plaintext per chunk: 64 * 30 = 1920 bytes.
const CHUNK_PLAINTEXT_MAX: usize = ENTRIES_PER_CHUNK * INDEX_ENTRY_SIZE;

/// Encrypted chunk overhead: 16 bytes (Poly1305 tag).
const CHUNK_TAG_SIZE: usize = 16;

/// Index file header size.
const HEADER_SIZE: usize = 36; // 8 + 24 + 4

/// An index entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub timestamp: TimestampBytes,
    pub fingerprint: Fingerprint,
    pub page_id: u16,
}

impl IndexEntry {
    pub fn serialize(&self, buf: &mut [u8; INDEX_ENTRY_SIZE]) {
        buf[0..16].copy_from_slice(&self.timestamp);
        buf[16..28].copy_from_slice(&self.fingerprint);
        buf[28..30].copy_from_slice(&self.page_id.to_le_bytes());
    }

    pub fn deserialize(buf: &[u8; INDEX_ENTRY_SIZE]) -> Self {
        let mut timestamp = [0u8; 16];
        timestamp.copy_from_slice(&buf[0..16]);
        let mut fingerprint = [0u8; 12];
        fingerprint.copy_from_slice(&buf[16..28]);
        let page_id = u16::from_le_bytes([buf[28], buf[29]]);
        IndexEntry {
            timestamp,
            fingerprint,
            page_id,
        }
    }
}

/// Derive a chunk nonce from seed and chunk index.
fn chunk_nonce(nonce_seed: &[u8; 24], chunk_idx: u32) -> [u8; 24] {
    let mut nonce = *nonce_seed;
    let idx_bytes = chunk_idx.to_le_bytes();
    // XOR the chunk index into the last 4 bytes of the nonce
    for i in 0..4 {
        nonce[20 + i] ^= idx_bytes[i];
    }
    nonce
}

/// Build AAD for a chunk.
fn chunk_aad(sequence: u64, chunk_idx: u32) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[0..8].copy_from_slice(&sequence.to_le_bytes());
    aad[8..12].copy_from_slice(&chunk_idx.to_le_bytes());
    aad
}

/// Read the index header from the host.
/// Returns (sequence, nonce_seed, total_entries) or None if no index exists.
pub fn read_index_header<H: HostInterface>(
    host: &mut H,
) -> Result<Option<(u64, [u8; 24], u32)>, IndexError> {
    let size = host.index_size().map_err(|_| IndexError::HostError)?;
    if size == 0 {
        return Ok(None);
    }
    if size < HEADER_SIZE as u64 {
        return Err(IndexError::Corrupt);
    }

    let mut hdr = [0u8; HEADER_SIZE];
    let n = host
        .index_read_at(0, &mut hdr)
        .map_err(|_| IndexError::HostError)?;
    if n < HEADER_SIZE {
        return Err(IndexError::Corrupt);
    }

    let sequence = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let mut nonce_seed = [0u8; 24];
    nonce_seed.copy_from_slice(&hdr[8..32]);
    let total_entries = u32::from_le_bytes(hdr[32..36].try_into().unwrap());

    Ok(Some((sequence, nonce_seed, total_entries)))
}

/// Stream-read the index, calling `callback` for each entry.
///
/// Reads one chunk at a time, decrypts, iterates entries.
/// RAM usage: one chunk buffer (~1936 bytes).
///
/// Returns the total number of entries processed.
pub fn read_index<H: HostInterface, F>(
    host: &mut H,
    trusted: &TrustedState,
    mut callback: F,
) -> Result<u32, IndexError>
where
    F: FnMut(&IndexEntry, u32) -> bool, // return false to stop
{
    let (sequence, nonce_seed, total_entries) = match read_index_header(host)? {
        Some(h) => h,
        None => return Ok(0),
    };

    // Replay detection
    if trusted.dir_sequence != 0 && sequence != trusted.dir_sequence {
        return Err(IndexError::TamperDetected);
    }

    let cipher = XChaCha20Poly1305::new((&trusted.device_key).into());

    let num_chunks = if total_entries == 0 {
        0
    } else {
        ((total_entries as usize - 1) / ENTRIES_PER_CHUNK + 1) as u32
    };

    let mut file_offset = HEADER_SIZE as u64;
    let mut global_idx: u32 = 0;
    let mut chunk_buf = [0u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE];

    for chunk_idx in 0..num_chunks {
        let entries_in_chunk = if chunk_idx == num_chunks - 1 {
            let remaining = total_entries - (chunk_idx * ENTRIES_PER_CHUNK as u32);
            remaining as usize
        } else {
            ENTRIES_PER_CHUNK
        };

        let chunk_ct_size = entries_in_chunk * INDEX_ENTRY_SIZE + CHUNK_TAG_SIZE;
        let n = host
            .index_read_at(file_offset, &mut chunk_buf[..chunk_ct_size])
            .map_err(|_| IndexError::HostError)?;
        if n < chunk_ct_size {
            return Err(IndexError::Corrupt);
        }
        file_offset += chunk_ct_size as u64;

        // Decrypt chunk in-place
        let plaintext_size = entries_in_chunk * INDEX_ENTRY_SIZE;
        let mut tag_bytes = [0u8; CHUNK_TAG_SIZE];
        tag_bytes.copy_from_slice(&chunk_buf[plaintext_size..plaintext_size + CHUNK_TAG_SIZE]);
        let tag = Tag::from_slice(&tag_bytes);
        let nonce = chunk_nonce(&nonce_seed, chunk_idx);
        let aad = chunk_aad(sequence, chunk_idx);

        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &aad,
                &mut chunk_buf[..plaintext_size],
                tag,
            )
            .map_err(|_| IndexError::TamperDetected)?;

        // Iterate entries in this chunk
        for i in 0..entries_in_chunk {
            let offset = i * INDEX_ENTRY_SIZE;
            let entry_buf: &[u8; INDEX_ENTRY_SIZE] =
                chunk_buf[offset..offset + INDEX_ENTRY_SIZE].try_into().unwrap();
            let entry = IndexEntry::deserialize(entry_buf);

            if !callback(&entry, global_idx) {
                return Ok(global_idx + 1);
            }
            global_idx += 1;
        }
    }

    Ok(global_idx)
}

/// Write a complete new index from an iterator of entries.
///
/// Streams entries into encrypted chunks, writing each chunk to the host
/// as it fills up. RAM usage: one chunk buffer.
///
/// Updates `trusted.dir_sequence` with the new sequence.
///
/// **After calling this, persist trusted_state to on-chip flash.**
pub fn write_index<H: HostInterface, P: Platform, I>(
    host: &mut H,
    platform: &mut P,
    trusted: &mut TrustedState,
    entries: I,
    total_entries: u32,
) -> Result<(), IndexError>
where
    I: Iterator<Item = IndexEntry>,
{
    trusted.dir_sequence += 1;
    let sequence = trusted.dir_sequence;

    let mut nonce_seed = [0u8; 24];
    platform.fill_random(&mut nonce_seed);

    // Write header
    let mut hdr = [0u8; HEADER_SIZE];
    hdr[0..8].copy_from_slice(&sequence.to_le_bytes());
    hdr[8..32].copy_from_slice(&nonce_seed);
    hdr[32..36].copy_from_slice(&total_entries.to_le_bytes());

    host.index_write_begin().map_err(|_| IndexError::HostError)?;
    host.index_write_append(&hdr)
        .map_err(|_| IndexError::HostError)?;

    let cipher = XChaCha20Poly1305::new((&trusted.device_key).into());

    let mut chunk_buf = [0u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE];
    let mut entries_in_chunk = 0usize;
    let mut chunk_idx: u32 = 0;

    for entry in entries {
        let offset = entries_in_chunk * INDEX_ENTRY_SIZE;
        let entry_slot: &mut [u8; INDEX_ENTRY_SIZE] =
            (&mut chunk_buf[offset..offset + INDEX_ENTRY_SIZE])
                .try_into()
                .unwrap();
        entry.serialize(entry_slot);
        entries_in_chunk += 1;

        if entries_in_chunk == ENTRIES_PER_CHUNK {
            flush_chunk(
                host,
                &cipher,
                &nonce_seed,
                sequence,
                chunk_idx,
                &mut chunk_buf,
                entries_in_chunk,
            )?;
            entries_in_chunk = 0;
            chunk_idx += 1;
        }
    }

    // Flush remaining entries
    if entries_in_chunk > 0 {
        flush_chunk(
            host,
            &cipher,
            &nonce_seed,
            sequence,
            chunk_idx,
            &mut chunk_buf,
            entries_in_chunk,
        )?;
    }

    host.index_write_commit()
        .map_err(|_| IndexError::HostError)?;

    Ok(())
}

fn flush_chunk<H: HostInterface>(
    host: &mut H,
    cipher: &XChaCha20Poly1305,
    nonce_seed: &[u8; 24],
    sequence: u64,
    chunk_idx: u32,
    chunk_buf: &mut [u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE],
    entries_in_chunk: usize,
) -> Result<(), IndexError> {
    let plaintext_size = entries_in_chunk * INDEX_ENTRY_SIZE;
    let nonce = chunk_nonce(nonce_seed, chunk_idx);
    let aad = chunk_aad(sequence, chunk_idx);

    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &aad,
            &mut chunk_buf[..plaintext_size],
        )
        .map_err(|_| IndexError::CryptoError)?;

    // Append ciphertext + tag
    chunk_buf[plaintext_size..plaintext_size + CHUNK_TAG_SIZE].copy_from_slice(&tag);
    let total = plaintext_size + CHUNK_TAG_SIZE;

    host.index_write_append(&chunk_buf[..total])
        .map_err(|_| IndexError::HostError)?;

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    HostError,
    Corrupt,
    CryptoError,
    /// Host replayed an old index or tampered with chunk data.
    TamperDetected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_host::FileHost;
    use evolu_core::crypto::timestamp_to_fingerprint;
    use evolu_core::timestamp::timestamp_to_bytes;
    use evolu_core::types::*;

    fn make_entry(millis: u64, page_id: u16) -> IndexEntry {
        let ts = timestamp_to_bytes(&Timestamp::new(
            Millis::new(millis).unwrap(),
            Counter::new(0),
            NodeId::MIN,
        ));
        IndexEntry {
            timestamp: ts,
            fingerprint: timestamp_to_fingerprint(&ts),
            page_id,
        }
    }

    use crate::std_platform::StdPlatform;

    fn make_trusted() -> TrustedState {
        TrustedState::new([0x42; 32])
    }

    fn make_platform() -> StdPlatform {
        StdPlatform
    }

    #[test]
    fn empty_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let trusted = make_trusted();

        let count = read_index(&mut host, &trusted, |_, _| true).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn write_and_read_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let entry = make_entry(1000, 1);
        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::once(entry), 1).unwrap();

        let mut entries = Vec::new();
        read_index(&mut host, &trusted, |e, _| {
            entries.push(*e);
            true
        })
        .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }

    #[test]
    fn write_and_read_many_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let entries: Vec<IndexEntry> = (0..200)
            .map(|i| make_entry(i * 1000, (i / 100) as u16))
            .collect();

        write_index(
            &mut host,
            &mut make_platform(),
            &mut trusted,
            entries.iter().copied(),
            entries.len() as u32,
        )
        .unwrap();

        let mut read_entries = Vec::new();
        let count = read_index(&mut host, &trusted, |e, _| {
            read_entries.push(*e);
            true
        })
        .unwrap();

        assert_eq!(count, 200);
        assert_eq!(read_entries, entries);
    }

    #[test]
    fn entries_span_multiple_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        // 64 entries per chunk, so 100 entries = 2 chunks (64 + 36)
        let entries: Vec<IndexEntry> = (0..100)
            .map(|i| make_entry(i * 100, 1))
            .collect();

        write_index(
            &mut host,
            &mut make_platform(),
            &mut trusted,
            entries.iter().copied(),
            100,
        )
        .unwrap();

        let mut count = 0u32;
        read_index(&mut host, &trusted, |_, _| {
            count += 1;
            true
        })
        .unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn early_stop() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let entries: Vec<IndexEntry> = (0..50)
            .map(|i| make_entry(i * 100, 1))
            .collect();

        write_index(&mut host, &mut make_platform(), &mut trusted, entries.iter().copied(), 50).unwrap();

        let mut count = 0u32;
        read_index(&mut host, &trusted, |_, _| {
            count += 1;
            count < 10 // stop after 10
        })
        .unwrap();
        assert_eq!(count, 10);
    }

    #[test]
    fn tamper_detection_corrupt_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        write_index(
            &mut host,
            &mut make_platform(),
            &mut trusted,
            core::iter::once(make_entry(1000, 1)),
            1,
        )
        .unwrap();

        // Corrupt the chunk data
        let path = dir.path().join("index.bin");
        let mut data = std::fs::read(&path).unwrap();
        data[HEADER_SIZE + 5] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let result = read_index(&mut host, &trusted, |_, _| true);
        assert_eq!(result, Err(IndexError::TamperDetected));
    }

    #[test]
    fn replay_detection() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        // Write version 1
        write_index(
            &mut host,
            &mut make_platform(),
            &mut trusted,
            core::iter::once(make_entry(1000, 1)),
            1,
        )
        .unwrap();
        let old_index = std::fs::read(dir.path().join("index.bin")).unwrap();

        // Write version 2 (trusted state advances)
        write_index(
            &mut host,
            &mut make_platform(),
            &mut trusted,
            [make_entry(1000, 1), make_entry(2000, 1)].iter().copied(),
            2,
        )
        .unwrap();

        // Replay old index
        std::fs::write(dir.path().join("index.bin"), &old_index).unwrap();

        let result = read_index(&mut host, &trusted, |_, _| true);
        assert_eq!(result, Err(IndexError::TamperDetected));
    }

    #[test]
    fn fingerprint_xor_over_range() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let entries: Vec<IndexEntry> = (0..10)
            .map(|i| make_entry(i * 100, 1))
            .collect();

        write_index(&mut host, &mut make_platform(), &mut trusted, entries.iter().copied(), 10).unwrap();

        // Compute fingerprint for range [2, 7) by streaming
        let mut fp = ZERO_FINGERPRINT;
        read_index(&mut host, &trusted, |e, idx| {
            if idx >= 2 && idx < 7 {
                fp = fingerprint_xor(&fp, &e.fingerprint);
            }
            true
        })
        .unwrap();

        // Verify against manual computation
        let mut expected = ZERO_FINGERPRINT;
        for i in 2..7 {
            expected = fingerprint_xor(&expected, &entries[i].fingerprint);
        }
        assert_eq!(fp, expected);
        assert_ne!(fp, ZERO_FINGERPRINT);
    }

    #[test]
    fn host_sees_only_encrypted_data() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let ts = timestamp_to_bytes(&Timestamp::new(
            Millis::new(1711234567890).unwrap(),
            Counter::new(0),
            NodeId::from_hex("deadbeef01234567").unwrap(),
        ));

        let entry = IndexEntry {
            timestamp: ts,
            fingerprint: timestamp_to_fingerprint(&ts),
            page_id: 42,
        };

        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::once(entry), 1).unwrap();

        // Read raw file
        let raw = std::fs::read(dir.path().join("index.bin")).unwrap();

        // The timestamp bytes should not appear in the encrypted file
        assert!(
            !raw.windows(16).any(|w| w == &ts),
            "Plaintext timestamp found in encrypted index!"
        );
    }

    #[test]
    fn sequence_increases_on_each_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();
        assert_eq!(trusted.dir_sequence, 0);

        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::empty(), 0).unwrap();
        assert_eq!(trusted.dir_sequence, 1);

        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::empty(), 0).unwrap();
        assert_eq!(trusted.dir_sequence, 2);
    }

    #[test]
    fn entry_serialize_deserialize() {
        let entry = make_entry(12345, 99);
        let mut buf = [0u8; INDEX_ENTRY_SIZE];
        entry.serialize(&mut buf);
        let restored = IndexEntry::deserialize(&buf);
        assert_eq!(restored, entry);
    }
}
