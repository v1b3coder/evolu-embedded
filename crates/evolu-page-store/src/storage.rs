//! Host-storage backend: streaming encrypted index + host data cache.
//!
//! Implements `StorageBackend` from `evolu-core`.

use crate::host::HostInterface;
use crate::index::{self, IndexEntry, IndexError};
use crate::trusted_state::TrustedState;
use evolu_core::crypto::timestamp_to_fingerprint;
use evolu_core::platform::Platform;
use evolu_core::storage::StorageBackend;
use evolu_core::types::*;

/// Maximum data blob size for cache reads.
const CACHE_BUF_SIZE: usize = 4096;

#[derive(Clone, Debug, PartialEq)]
pub enum HostStorageError {
    Host,
    Index(IndexError),
    CacheFull,
}

impl From<IndexError> for HostStorageError {
    fn from(e: IndexError) -> Self {
        HostStorageError::Index(e)
    }
}

/// Host-storage backend.
///
/// - Timestamp index: streamed from host, encrypted in chunks, signed
/// - Data: stored in host cache as raw EncryptedDbChange blobs
///
/// After any mutation, persist `trusted_state()` to on-chip flash.
pub struct HostStorage<H: HostInterface, P: Platform> {
    host: H,
    platform: P,
    trusted: TrustedState,
    cache_buf: [u8; CACHE_BUF_SIZE],
    cache_len: usize,
}

impl<H: HostInterface, P: Platform> HostStorage<H, P> {
    pub fn new(host: H, platform: P, trusted: TrustedState) -> Self {
        HostStorage {
            host,
            platform,
            trusted,
            cache_buf: [0u8; CACHE_BUF_SIZE],
            cache_len: 0,
        }
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Get trusted state. **Persist to on-chip flash after every mutation.**
    pub fn trusted_state(&self) -> &TrustedState {
        &self.trusted
    }
}

impl<H: HostInterface, P: Platform> StorageBackend for HostStorage<H, P> {
    type Error = HostStorageError;

    fn size(&mut self) -> Result<u32, Self::Error> {
        let header = index::read_index_header(&mut self.host)?;
        match header {
            None => Ok(0),
            Some((sequence, _, count)) => {
                if self.trusted.dir_sequence != 0 && sequence != self.trusted.dir_sequence {
                    return Err(IndexError::TamperDetected.into());
                }
                Ok(count)
            }
        }
    }

    fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, Self::Error> {
        if begin >= end {
            return Ok(ZERO_FINGERPRINT);
        }
        let mut fp = ZERO_FINGERPRINT;
        index::read_index(&mut self.host, &self.trusted, |entry, idx| {
            if idx >= begin && idx < end {
                fp = fingerprint_xor(&fp, &entry.fingerprint);
            }
            idx < end
        })?;
        Ok(fp)
    }

    fn iterate(
        &mut self,
        begin: u32,
        end: u32,
        cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool,
    ) -> Result<(), Self::Error> {
        if begin >= end {
            return Ok(());
        }
        index::read_index(&mut self.host, &self.trusted, |entry, idx| {
            if idx >= end {
                return false;
            }
            if idx >= begin {
                return cb(&entry.timestamp, idx);
            }
            true
        })?;
        Ok(())
    }

    fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), Self::Error> {
        // Read existing entries
        let mut entries: heapless::Vec<IndexEntry, 4096> = heapless::Vec::new();
        index::read_index(&mut self.host, &self.trusted, |entry, _| {
            let _ = entries.push(*entry);
            true
        })?;

        // Check duplicate
        if entries.iter().any(|e| e.timestamp == *ts) {
            return Ok(());
        }

        // Sorted insert
        let pos = entries
            .iter()
            .position(|e| e.timestamp > *ts)
            .unwrap_or(entries.len());

        let new_entry = IndexEntry {
            timestamp: *ts,
            fingerprint: timestamp_to_fingerprint(ts),
            page_id: 0, // unused in host-storage, kept for index format compat
        };

        entries.insert(pos, new_entry).map_err(|_| HostStorageError::CacheFull)?;

        // Store data in host cache
        if !data.is_empty() {
            self.host.cache_store(ts, data).map_err(|_| HostStorageError::Host)?;
        }

        // Rewrite index
        let count = entries.len() as u32;
        index::write_index(&mut self.host, &mut self.platform, &mut self.trusted, entries.into_iter(), count)?;

        Ok(())
    }

    fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, Self::Error> {
        let n = self.host.cache_read(ts, &mut self.cache_buf).map_err(|_| HostStorageError::Host)?;
        if n == 0 {
            return Ok(None);
        }
        self.cache_len = n;
        Ok(Some(&self.cache_buf[..self.cache_len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_host::FileHost;
    use evolu_core::timestamp::timestamp_to_bytes;

    fn make_ts(millis: u64) -> TimestampBytes {
        timestamp_to_bytes(&Timestamp::new(
            Millis::new(millis).unwrap(),
            Counter::new(0),
            NodeId::MIN,
        ))
    }

    use crate::std_platform::StdPlatform;

    fn create_storage() -> HostStorage<FileHost, StdPlatform> {
        let dir = tempfile::tempdir().unwrap();
        let host = FileHost::new(dir.into_path()).unwrap();
        let trusted = TrustedState::new([0x42; 32]);
        HostStorage::new(host, StdPlatform, trusted)
    }

    #[test]
    fn empty() {
        let mut s = create_storage();
        assert_eq!(s.size().unwrap(), 0);
    }

    #[test]
    fn insert_and_count() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"data A").unwrap();
        s.insert(&make_ts(200), b"data B").unwrap();
        s.insert(&make_ts(50), b"data C").unwrap();
        assert_eq!(s.size().unwrap(), 3);
    }

    #[test]
    fn idempotent() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"data").unwrap();
        s.insert(&make_ts(100), b"data").unwrap();
        assert_eq!(s.size().unwrap(), 1);
    }

    #[test]
    fn sorted_order() {
        let mut s = create_storage();
        s.insert(&make_ts(300), b"c").unwrap();
        s.insert(&make_ts(100), b"a").unwrap();
        s.insert(&make_ts(200), b"b").unwrap();

        let mut ts_list = Vec::new();
        s.iterate(0, 3, &mut |ts, _| { ts_list.push(*ts); true }).unwrap();
        assert!(ts_list[0] < ts_list[1] && ts_list[1] < ts_list[2]);
    }

    #[test]
    fn read_data() {
        let mut s = create_storage();
        let ts = make_ts(100);
        s.insert(&ts, b"Hello world!").unwrap();

        let data = s.read(&ts).unwrap().unwrap();
        assert_eq!(data, b"Hello world!");
    }

    #[test]
    fn read_miss() {
        let mut s = create_storage();
        let ts = make_ts(999);
        assert!(s.read(&ts).unwrap().is_none());
    }

    #[test]
    fn iterate_range() {
        let mut s = create_storage();
        for i in 0..10 {
            s.insert(&make_ts(i * 100), &[i as u8]).unwrap();
        }
        let mut idxs = Vec::new();
        s.iterate(3, 7, &mut |_, idx| { idxs.push(idx); true }).unwrap();
        assert_eq!(idxs, vec![3, 4, 5, 6]);
    }

    #[test]
    fn fingerprint_consistency() {
        let mut s = create_storage();
        let ts1 = make_ts(100);
        let ts2 = make_ts(200);
        let ts3 = make_ts(300);
        s.insert(&ts1, b"a").unwrap();
        s.insert(&ts2, b"b").unwrap();
        s.insert(&ts3, b"c").unwrap();

        let fp_all = s.fingerprint(0, 3).unwrap();
        let f1 = timestamp_to_fingerprint(&ts1);
        let f2 = timestamp_to_fingerprint(&ts2);
        let f3 = timestamp_to_fingerprint(&ts3);
        assert_eq!(fp_all, fingerprint_xor(&fingerprint_xor(&f1, &f2), &f3));
    }

    #[test]
    fn fingerprint_partitions() {
        let mut s = create_storage();
        for i in 0..5 { s.insert(&make_ts(i * 100), &[i as u8]).unwrap(); }

        let fp_a = s.fingerprint(0, 2).unwrap();
        let fp_b = s.fingerprint(2, 5).unwrap();
        let fp_all = s.fingerprint(0, 5).unwrap();
        assert_eq!(fingerprint_xor(&fp_a, &fp_b), fp_all);
    }

    #[test]
    fn replay_detection() {
        let mut s = create_storage();
        s.insert(&make_ts(100), b"v1").unwrap();
        let old_idx = std::fs::read(s.host().base_dir().join("index.bin")).unwrap();

        s.insert(&make_ts(200), b"v2").unwrap();

        std::fs::write(s.host().base_dir().join("index.bin"), &old_idx).unwrap();
        assert!(matches!(s.size(), Err(HostStorageError::Index(IndexError::TamperDetected))));
    }

    #[test]
    fn data_encrypted_on_host() {
        let mut s = create_storage();
        let ts = make_ts(12345678);
        s.insert(&ts, b"secret payload").unwrap();

        let raw = std::fs::read(s.host().base_dir().join("index.bin")).unwrap();
        assert!(!raw.windows(16).any(|w| w == &ts), "timestamp in index plaintext");
    }

    #[test]
    fn many_entries() {
        let mut s = create_storage();
        for i in 0..100 { s.insert(&make_ts(i * 10), &[i as u8]).unwrap(); }
        assert_eq!(s.size().unwrap(), 100);

        let mut prev = [0u8; 16];
        let mut count = 0;
        s.iterate(0, 100, &mut |ts, _| {
            if count > 0 { assert!(ts > &prev); }
            prev = *ts;
            count += 1;
            true
        }).unwrap();
        assert_eq!(count, 100);
    }
}
