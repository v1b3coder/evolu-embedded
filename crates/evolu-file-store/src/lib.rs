//! File-based storage backend for Evolu.
//!
//! Simple Vec-backed `StorageBackend` for demo and testing on std systems.
//! No encryption, no streaming — just a sorted list in memory.

use evolu_core::crypto::timestamp_to_fingerprint;
use evolu_core::storage::StorageBackend;
use evolu_core::types::*;

#[derive(Clone, Debug)]
struct Entry {
    timestamp: TimestampBytes,
    fingerprint: Fingerprint,
    data: Vec<u8>,
}

/// Simple Vec-backed storage for demo and testing.
pub struct FileStorage {
    entries: Vec<Entry>,
    read_buf: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FileStorageError {
    NotFound,
}

impl FileStorage {
    pub fn new() -> Self {
        FileStorage {
            entries: Vec::new(),
            read_buf: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for FileStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for FileStorage {
    type Error = FileStorageError;

    fn size(&mut self) -> Result<u32, Self::Error> {
        Ok(self.entries.len() as u32)
    }

    fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, Self::Error> {
        let mut fp = ZERO_FINGERPRINT;
        let b = begin as usize;
        let e = (end as usize).min(self.entries.len());
        for entry in &self.entries[b..e] {
            fp = fingerprint_xor(&fp, &entry.fingerprint);
        }
        Ok(fp)
    }

    fn iterate(
        &mut self,
        begin: u32,
        end: u32,
        cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool,
    ) -> Result<(), Self::Error> {
        let b = begin as usize;
        let e = (end as usize).min(self.entries.len());
        for (i, entry) in self.entries[b..e].iter().enumerate() {
            if !cb(&entry.timestamp, begin + i as u32) {
                break;
            }
        }
        Ok(())
    }

    fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), Self::Error> {
        if self.entries.iter().any(|e| e.timestamp == *ts) {
            return Ok(());
        }

        let pos = self
            .entries
            .iter()
            .position(|e| e.timestamp > *ts)
            .unwrap_or(self.entries.len());

        self.entries.insert(
            pos,
            Entry {
                timestamp: *ts,
                fingerprint: timestamp_to_fingerprint(ts),
                data: data.to_vec(),
            },
        );

        Ok(())
    }

    fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, Self::Error> {
        if let Some(entry) = self.entries.iter().find(|e| e.timestamp == *ts) {
            self.read_buf = entry.data.clone();
            Ok(Some(&self.read_buf))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evolu_core::timestamp::timestamp_to_bytes;

    fn make_ts(millis: u64) -> TimestampBytes {
        timestamp_to_bytes(&Timestamp::new(
            Millis::new(millis).unwrap(),
            Counter::new(0),
            NodeId::MIN,
        ))
    }

    #[test]
    fn empty() {
        let mut s = FileStorage::new();
        assert_eq!(s.size().unwrap(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn insert_and_count() {
        let mut s = FileStorage::new();
        s.insert(&make_ts(100), b"A").unwrap();
        s.insert(&make_ts(200), b"B").unwrap();
        s.insert(&make_ts(50), b"C").unwrap();
        assert_eq!(s.size().unwrap(), 3);
    }

    #[test]
    fn idempotent() {
        let mut s = FileStorage::new();
        s.insert(&make_ts(100), b"data").unwrap();
        s.insert(&make_ts(100), b"data").unwrap();
        assert_eq!(s.size().unwrap(), 1);
    }

    #[test]
    fn sorted_order() {
        let mut s = FileStorage::new();
        s.insert(&make_ts(300), b"c").unwrap();
        s.insert(&make_ts(100), b"a").unwrap();
        s.insert(&make_ts(200), b"b").unwrap();

        let mut ts_list = Vec::new();
        s.iterate(0, 3, &mut |ts, _| { ts_list.push(*ts); true }).unwrap();
        assert!(ts_list[0] < ts_list[1] && ts_list[1] < ts_list[2]);
    }

    #[test]
    fn read_data() {
        let mut s = FileStorage::new();
        let ts = make_ts(100);
        s.insert(&ts, b"Hello!").unwrap();
        assert_eq!(s.read(&ts).unwrap().unwrap(), b"Hello!");
    }

    #[test]
    fn read_miss() {
        let mut s = FileStorage::new();
        assert!(s.read(&make_ts(999)).unwrap().is_none());
    }

    #[test]
    fn iterate_range() {
        let mut s = FileStorage::new();
        for i in 0..10 { s.insert(&make_ts(i * 100), &[i as u8]).unwrap(); }

        let mut idxs = Vec::new();
        s.iterate(3, 7, &mut |_, idx| { idxs.push(idx); true }).unwrap();
        assert_eq!(idxs, vec![3, 4, 5, 6]);
    }

    #[test]
    fn fingerprint_partitions() {
        let mut s = FileStorage::new();
        for i in 0..5 { s.insert(&make_ts(i * 100), &[i as u8]).unwrap(); }

        let a = s.fingerprint(0, 2).unwrap();
        let b = s.fingerprint(2, 5).unwrap();
        let all = s.fingerprint(0, 5).unwrap();
        assert_eq!(fingerprint_xor(&a, &b), all);
    }
}
