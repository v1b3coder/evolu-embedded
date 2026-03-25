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

use crate::host::HostStore;
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
pub fn read_index_header<H: HostStore>(
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
pub fn read_index<H: HostStore, F>(
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
pub fn write_index<H: HostStore, P: Platform, I>(
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

fn flush_chunk<H: HostStore>(
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
    /// Batch too large for fixed-capacity buffer.
    BatchFull,
}

// ── IndexReader ─────────────────────────────────────────────────────

/// Streaming index reader — decrypts one chunk at a time.
///
/// Does NOT borrow the host. Each method takes `&mut H` transiently,
/// so the caller can interleave reads and writes through the same host.
pub struct IndexReader {
    nonce_seed: [u8; 24],
    sequence: u64,
    total_entries: u32,
    num_chunks: u32,
    // Position tracking
    file_offset: u64,
    chunk_idx: u32,
    pos_in_chunk: usize,
    entries_in_current_chunk: usize,
    global_idx: u32,
    // Decrypted chunk
    chunk_buf: [u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE],
    chunk_loaded: bool,
    exhausted: bool,
    // Cipher key (stored to avoid re-init per chunk)
    device_key: [u8; 32],
}

impl IndexReader {
    /// Open the index for streaming reads.
    /// Returns `None` if no index exists on the host.
    pub fn open<H: HostStore>(
        host: &mut H,
        trusted: &TrustedState,
    ) -> Result<Option<Self>, IndexError> {
        let (sequence, nonce_seed, total_entries) = match read_index_header(host)? {
            Some(h) => h,
            None => return Ok(None),
        };

        // Replay detection
        if trusted.dir_sequence != 0 && sequence != trusted.dir_sequence {
            return Err(IndexError::TamperDetected);
        }

        let num_chunks = if total_entries == 0 {
            0
        } else {
            ((total_entries as usize - 1) / ENTRIES_PER_CHUNK + 1) as u32
        };

        Ok(Some(IndexReader {
            nonce_seed,
            sequence,
            total_entries,
            num_chunks,
            file_offset: HEADER_SIZE as u64,
            chunk_idx: 0,
            pos_in_chunk: 0,
            entries_in_current_chunk: 0,
            global_idx: 0,
            chunk_buf: [0u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE],
            chunk_loaded: false,
            exhausted: num_chunks == 0,
            device_key: trusted.device_key,
        }))
    }

    /// Total entries in the index (from header).
    pub fn total_entries(&self) -> u32 {
        self.total_entries
    }

    /// Read the next entry. Returns `None` when exhausted.
    pub fn next<H: HostStore>(
        &mut self,
        host: &mut H,
    ) -> Result<Option<IndexEntry>, IndexError> {
        if self.exhausted {
            return Ok(None);
        }

        // Load next chunk if needed
        if !self.chunk_loaded || self.pos_in_chunk >= self.entries_in_current_chunk {
            if self.chunk_idx >= self.num_chunks {
                self.exhausted = true;
                return Ok(None);
            }
            self.load_chunk(host)?;
        }

        let offset = self.pos_in_chunk * INDEX_ENTRY_SIZE;
        let entry_buf: &[u8; INDEX_ENTRY_SIZE] =
            self.chunk_buf[offset..offset + INDEX_ENTRY_SIZE]
                .try_into()
                .unwrap();
        let entry = IndexEntry::deserialize(entry_buf);
        self.pos_in_chunk += 1;
        self.global_idx += 1;

        Ok(Some(entry))
    }

    fn load_chunk<H: HostStore>(&mut self, host: &mut H) -> Result<(), IndexError> {
        let entries_in_chunk = if self.chunk_idx == self.num_chunks - 1 {
            (self.total_entries - (self.chunk_idx * ENTRIES_PER_CHUNK as u32)) as usize
        } else {
            ENTRIES_PER_CHUNK
        };

        let chunk_ct_size = entries_in_chunk * INDEX_ENTRY_SIZE + CHUNK_TAG_SIZE;
        let n = host
            .index_read_at(self.file_offset, &mut self.chunk_buf[..chunk_ct_size])
            .map_err(|_| IndexError::HostError)?;
        if n < chunk_ct_size {
            return Err(IndexError::Corrupt);
        }
        self.file_offset += chunk_ct_size as u64;

        // Decrypt in-place
        let plaintext_size = entries_in_chunk * INDEX_ENTRY_SIZE;
        let mut tag_bytes = [0u8; CHUNK_TAG_SIZE];
        tag_bytes
            .copy_from_slice(&self.chunk_buf[plaintext_size..plaintext_size + CHUNK_TAG_SIZE]);
        let tag = Tag::from_slice(&tag_bytes);
        let nonce = chunk_nonce(&self.nonce_seed, self.chunk_idx);
        let aad = chunk_aad(self.sequence, self.chunk_idx);

        let cipher = XChaCha20Poly1305::new((&self.device_key).into());
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &aad,
                &mut self.chunk_buf[..plaintext_size],
                tag,
            )
            .map_err(|_| IndexError::TamperDetected)?;

        self.entries_in_current_chunk = entries_in_chunk;
        self.pos_in_chunk = 0;
        self.chunk_idx += 1;
        self.chunk_loaded = true;

        Ok(())
    }
}

// ── IndexWriter ─────────────────────────────────────────────────────

/// Streaming index writer — encrypts and flushes one chunk at a time.
///
/// Does NOT borrow the host. Each method takes `&mut H` transiently.
pub struct IndexWriter {
    sequence: u64,
    nonce_seed: [u8; 24],
    chunk_buf: [u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE],
    entries_in_chunk: usize,
    chunk_idx: u32,
    device_key: [u8; 32],
}

impl IndexWriter {
    /// Begin a new index write. Writes the header to host.
    pub fn begin<H: HostStore, P: Platform>(
        host: &mut H,
        platform: &mut P,
        trusted: &mut TrustedState,
        total_entries: u32,
    ) -> Result<Self, IndexError> {
        trusted.dir_sequence += 1;
        let sequence = trusted.dir_sequence;

        let mut nonce_seed = [0u8; 24];
        platform.fill_random(&mut nonce_seed);

        let mut hdr = [0u8; HEADER_SIZE];
        hdr[0..8].copy_from_slice(&sequence.to_le_bytes());
        hdr[8..32].copy_from_slice(&nonce_seed);
        hdr[32..36].copy_from_slice(&total_entries.to_le_bytes());

        host.index_write_begin()
            .map_err(|_| IndexError::HostError)?;
        host.index_write_append(&hdr)
            .map_err(|_| IndexError::HostError)?;

        Ok(IndexWriter {
            sequence,
            nonce_seed,
            chunk_buf: [0u8; CHUNK_PLAINTEXT_MAX + CHUNK_TAG_SIZE],
            entries_in_chunk: 0,
            chunk_idx: 0,
            device_key: trusted.device_key,
        })
    }

    /// Push one entry. Flushes a chunk when full.
    pub fn push<H: HostStore>(
        &mut self,
        host: &mut H,
        entry: IndexEntry,
    ) -> Result<(), IndexError> {
        let offset = self.entries_in_chunk * INDEX_ENTRY_SIZE;
        let entry_slot: &mut [u8; INDEX_ENTRY_SIZE] =
            (&mut self.chunk_buf[offset..offset + INDEX_ENTRY_SIZE])
                .try_into()
                .unwrap();
        entry.serialize(entry_slot);
        self.entries_in_chunk += 1;

        if self.entries_in_chunk == ENTRIES_PER_CHUNK {
            self.flush(host)?;
        }

        Ok(())
    }

    /// Flush remaining entries and commit the index.
    pub fn finish<H: HostStore>(mut self, host: &mut H) -> Result<(), IndexError> {
        if self.entries_in_chunk > 0 {
            self.flush(host)?;
        }
        host.index_write_commit()
            .map_err(|_| IndexError::HostError)?;
        Ok(())
    }

    fn flush<H: HostStore>(&mut self, host: &mut H) -> Result<(), IndexError> {
        flush_chunk(
            host,
            &XChaCha20Poly1305::new((&self.device_key).into()),
            &self.nonce_seed,
            self.sequence,
            self.chunk_idx,
            &mut self.chunk_buf,
            self.entries_in_chunk,
        )?;
        self.entries_in_chunk = 0;
        self.chunk_idx += 1;
        Ok(())
    }
}

// ── Streaming merge ─────────────────────────────────────────────────

/// Count how many entries in `new_entries` already exist in the old index.
/// `new_entries` must be sorted by timestamp.
///
/// Uses one `IndexReader` pass (one chunk buffer).
pub fn pre_scan_duplicates<H: HostStore>(
    host: &mut H,
    trusted: &TrustedState,
    new_entries: &[IndexEntry],
) -> Result<u32, IndexError> {
    let mut reader = match IndexReader::open(host, trusted)? {
        Some(r) => r,
        None => return Ok(0),
    };

    let mut dup_count = 0u32;
    let mut new_idx = 0usize;

    // Merge-scan: both streams are sorted, advance the smaller
    while new_idx < new_entries.len() {
        let old = match reader.next(host)? {
            Some(e) => e,
            None => break,
        };

        // Advance new_idx past any entries smaller than current old entry
        while new_idx < new_entries.len() && new_entries[new_idx].timestamp < old.timestamp {
            new_idx += 1;
        }

        // Check for match
        if new_idx < new_entries.len() && new_entries[new_idx].timestamp == old.timestamp {
            dup_count += 1;
            new_idx += 1;
        }
    }

    Ok(dup_count)
}

/// Merge old index with sorted new entries, writing a new index.
///
/// Two-cursor merge: reads old index one chunk at a time via `IndexReader`,
/// writes new index one chunk at a time via `IndexWriter`.
///
/// `new_entries` must be sorted by timestamp and de-duplicated against the old
/// index (use `pre_scan_duplicates` to compute `total_entries` correctly).
///
/// RAM: ~4 KB (one read buffer + one write buffer).
///
/// **After calling this, persist trusted_state to on-chip flash.**
pub fn streaming_merge_write<H: HostStore, P: Platform>(
    host: &mut H,
    platform: &mut P,
    trusted: &mut TrustedState,
    new_entries: &[IndexEntry],
    total_entries: u32,
) -> Result<(), IndexError> {
    let mut reader = IndexReader::open(host, trusted)?;
    let mut writer = IndexWriter::begin(host, platform, trusted, total_entries)?;

    let mut new_idx = 0usize;
    let mut old_entry: Option<IndexEntry> = match &mut reader {
        Some(r) => r.next(host)?,
        None => None,
    };

    loop {
        let have_old = old_entry.is_some();
        let have_new = new_idx < new_entries.len();

        if !have_old && !have_new {
            break;
        }

        let emit_old = if have_old && have_new {
            let old_ts = &old_entry.as_ref().unwrap().timestamp;
            let new_ts = &new_entries[new_idx].timestamp;
            // Skip duplicate new entry (old wins — it's already in the index)
            if old_ts == new_ts {
                new_idx += 1;
            }
            old_ts <= new_ts
        } else {
            have_old
        };

        if emit_old {
            writer.push(host, old_entry.unwrap())?;
            old_entry = match &mut reader {
                Some(r) => r.next(host)?,
                None => None,
            };
        } else {
            writer.push(host, new_entries[new_idx])?;
            new_idx += 1;
        }
    }

    writer.finish(host)?;
    Ok(())
}

/// Validate the index against trusted state on boot.
///
/// Handles the crash window where the index was committed but `TrustedState`
/// was not persisted to flash. If `disk_sequence == trusted.dir_sequence + 1`,
/// accepts the index and advances `dir_sequence`.
///
/// Returns `Ok(())` if consistent (or recovered). Returns
/// `Err(TamperDetected)` if the sequence is out of range.
pub fn validate_and_recover<H: HostStore>(
    host: &mut H,
    trusted: &mut TrustedState,
) -> Result<(), IndexError> {
    let (disk_seq, _, _) = match read_index_header(host)? {
        Some(h) => h,
        None => return Ok(()), // no index yet
    };

    if disk_seq == trusted.dir_sequence {
        Ok(()) // consistent
    } else if trusted.dir_sequence != 0 && disk_seq == trusted.dir_sequence + 1 {
        // Crashed after index commit but before persisting TrustedState.
        trusted.dir_sequence = disk_seq;
        Ok(())
    } else if trusted.dir_sequence == 0 {
        // Fresh device, accept whatever is on disk (first boot).
        trusted.dir_sequence = disk_seq;
        Ok(())
    } else {
        Err(IndexError::TamperDetected)
    }
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

    use evolu_std_platform::StdPlatform;

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

    // ── IndexReader tests ───────────────────────────────────────

    #[test]
    fn index_reader_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let trusted = make_trusted();

        let reader = IndexReader::open(&mut host, &trusted).unwrap();
        assert!(reader.is_none());
    }

    #[test]
    fn index_reader_matches_read_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let entries: Vec<IndexEntry> = (0..200)
            .map(|i| make_entry(i * 1000, (i / 100) as u16))
            .collect();
        write_index(&mut host, &mut make_platform(), &mut trusted, entries.iter().copied(), 200).unwrap();

        // Read with callback
        let mut cb_entries = Vec::new();
        read_index(&mut host, &trusted, |e, _| { cb_entries.push(*e); true }).unwrap();

        // Read with IndexReader
        let mut reader = IndexReader::open(&mut host, &trusted).unwrap().unwrap();
        let mut reader_entries = Vec::new();
        while let Some(entry) = reader.next(&mut host).unwrap() {
            reader_entries.push(entry);
        }

        assert_eq!(reader_entries, cb_entries);
        assert_eq!(reader_entries, entries);
    }

    // ── IndexWriter tests ───────────────────────────────────────

    #[test]
    fn index_writer_produces_readable_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let entries: Vec<IndexEntry> = (0..100)
            .map(|i| make_entry(i * 100, 1))
            .collect();

        let mut writer = IndexWriter::begin(&mut host, &mut make_platform(), &mut trusted, 100).unwrap();
        for e in &entries {
            writer.push(&mut host, *e).unwrap();
        }
        writer.finish(&mut host).unwrap();

        // Verify via read_index
        let mut read_entries = Vec::new();
        read_index(&mut host, &trusted, |e, _| { read_entries.push(*e); true }).unwrap();
        assert_eq!(read_entries, entries);
    }

    // ── pre_scan_duplicates tests ───────────────────────────────

    #[test]
    fn pre_scan_no_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old: Vec<IndexEntry> = (0..5).map(|i| make_entry(i * 100, 1)).collect();
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 5).unwrap();

        let new: Vec<IndexEntry> = (5..8).map(|i| make_entry(i * 100, 1)).collect();
        let dups = pre_scan_duplicates(&mut host, &trusted, &new).unwrap();
        assert_eq!(dups, 0);
    }

    #[test]
    fn pre_scan_all_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old: Vec<IndexEntry> = (0..5).map(|i| make_entry(i * 100, 1)).collect();
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 5).unwrap();

        let new: Vec<IndexEntry> = (1..4).map(|i| make_entry(i * 100, 1)).collect();
        let dups = pre_scan_duplicates(&mut host, &trusted, &new).unwrap();
        assert_eq!(dups, 3);
    }

    #[test]
    fn pre_scan_partial_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old: Vec<IndexEntry> = (0..5).map(|i| make_entry(i * 100, 1)).collect();
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 5).unwrap();

        // new = [200, 400, 600] — 200 and 400 are dupes, 600 is new
        let new = vec![make_entry(200, 1), make_entry(400, 1), make_entry(600, 1)];
        let dups = pre_scan_duplicates(&mut host, &trusted, &new).unwrap();
        assert_eq!(dups, 2);
    }

    #[test]
    fn pre_scan_empty_old() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let trusted = make_trusted();

        let new = vec![make_entry(100, 1), make_entry(200, 1)];
        let dups = pre_scan_duplicates(&mut host, &trusted, &new).unwrap();
        assert_eq!(dups, 0);
    }

    // ── streaming_merge_write tests ─────────────────────────────

    #[test]
    fn merge_into_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let new = vec![make_entry(100, 1), make_entry(200, 1), make_entry(300, 1)];
        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &new, 3).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        assert_eq!(result, new);
    }

    #[test]
    fn merge_empty_new() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old: Vec<IndexEntry> = (0..5).map(|i| make_entry(i * 100, 1)).collect();
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 5).unwrap();

        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &[], 5).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        assert_eq!(result, old);
    }

    #[test]
    fn merge_interleaved() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        // old = [100, 300, 500]
        let old = vec![make_entry(100, 1), make_entry(300, 1), make_entry(500, 1)];
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 3).unwrap();

        // new = [200, 400]
        let new = vec![make_entry(200, 1), make_entry(400, 1)];
        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &new, 5).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        let expected: Vec<IndexEntry> = vec![100, 200, 300, 400, 500]
            .into_iter().map(|m| make_entry(m, 1)).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn merge_all_before() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old = vec![make_entry(500, 1), make_entry(600, 1)];
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 2).unwrap();

        let new = vec![make_entry(100, 1), make_entry(200, 1)];
        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &new, 4).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        let expected: Vec<IndexEntry> = vec![100, 200, 500, 600]
            .into_iter().map(|m| make_entry(m, 1)).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn merge_all_after() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old = vec![make_entry(100, 1), make_entry(200, 1)];
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 2).unwrap();

        let new = vec![make_entry(500, 1), make_entry(600, 1)];
        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &new, 4).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        let expected: Vec<IndexEntry> = vec![100, 200, 500, 600]
            .into_iter().map(|m| make_entry(m, 1)).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn merge_with_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        let old = vec![make_entry(100, 1), make_entry(200, 1), make_entry(300, 1)];
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 3).unwrap();

        // new includes 200 (duplicate) and 250 (new)
        let new = vec![make_entry(200, 1), make_entry(250, 1)];
        // Pre-scan to get correct total
        let dups = pre_scan_duplicates(&mut host, &trusted, &new).unwrap();
        assert_eq!(dups, 1);
        let total = 3 + 2 - dups;
        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &new, total).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        let expected: Vec<IndexEntry> = vec![100, 200, 250, 300]
            .into_iter().map(|m| make_entry(m, 1)).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn merge_large_crosses_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        // 200 old entries (spans ~4 chunks)
        let old: Vec<IndexEntry> = (0..200).map(|i| make_entry(i * 10, 1)).collect();
        write_index(&mut host, &mut make_platform(), &mut trusted, old.iter().copied(), 200).unwrap();

        // 50 new entries interleaved
        let new: Vec<IndexEntry> = (0..50).map(|i| make_entry(i * 10 + 5, 1)).collect();
        let dups = pre_scan_duplicates(&mut host, &trusted, &new).unwrap();
        assert_eq!(dups, 0);
        streaming_merge_write(&mut host, &mut make_platform(), &mut trusted, &new, 250).unwrap();

        let mut result = Vec::new();
        read_index(&mut host, &trusted, |e, _| { result.push(*e); true }).unwrap();
        assert_eq!(result.len(), 250);

        // Verify sorted order
        for w in result.windows(2) {
            assert!(w[0].timestamp < w[1].timestamp);
        }
    }

    // ── validate_and_recover tests ──────────────────────────────

    #[test]
    fn validate_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::once(make_entry(100, 1)), 1).unwrap();
        // trusted.dir_sequence is now 1, matching the index
        assert!(validate_and_recover(&mut host, &mut trusted).is_ok());
        assert_eq!(trusted.dir_sequence, 1);
    }

    #[test]
    fn validate_off_by_one_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::once(make_entry(100, 1)), 1).unwrap();
        // Simulate crash: roll back dir_sequence
        trusted.dir_sequence = 0;

        // First write sets dir_sequence to 1 and the index has sequence 1.
        // After rollback, trusted says 0 but disk says 1.
        // That's the off-by-one case.
        assert!(validate_and_recover(&mut host, &mut trusted).is_ok());
        assert_eq!(trusted.dir_sequence, 1);
    }

    #[test]
    fn validate_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();

        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::once(make_entry(100, 1)), 1).unwrap();
        write_index(&mut host, &mut make_platform(), &mut trusted, core::iter::once(make_entry(100, 1)), 1).unwrap();
        // trusted.dir_sequence is now 2
        // Manually set trusted to 5 — simulates a large gap
        trusted.dir_sequence = 5;

        let result = validate_and_recover(&mut host, &mut trusted);
        assert_eq!(result, Err(IndexError::TamperDetected));
    }

    #[test]
    fn validate_empty_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = FileHost::new(dir.path()).unwrap();
        let mut trusted = make_trusted();
        trusted.dir_sequence = 42;

        // No index exists — should be ok
        assert!(validate_and_recover(&mut host, &mut trusted).is_ok());
    }
}
