//! Master directory page for the encrypted paged storage.
//!
//! Page 0 is the directory — it maps page IDs to their key ranges and
//! pre-aggregated fingerprints. This allows the device to find the right
//! data page without scanning, and to compute sync fingerprints for
//! full pages without reading them.

use evolu_core::types::*;

/// Maximum entries in a single directory page (~2KB / 65 bytes per entry ≈ 31).
pub const MAX_DIR_ENTRIES: usize = 30;

/// Page type discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    /// Timestamp pages: sorted TimestampBytes entries for RBSR sync.
    Timestamp = 1,
    /// History pages: sorted (table, id, column, timestamp) → value for CRDT LWW.
    History = 2,
}

impl PageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(PageType::Timestamp),
            2 => Some(PageType::History),
            _ => None,
        }
    }
}

/// A single entry in the master directory.
///
/// Binary layout (65 bytes):
/// - page_id: u16 (2)
/// - page_type: u8 (1)
/// - count: u16 (2)
/// - first_key: [u8; 16] (16)
/// - last_key: [u8; 16] (16)
/// - xor_fingerprint: [u8; 12] (12)
/// Total: 49 bytes — leaves room for ~41 entries per 2KB page.
#[derive(Clone, Debug, PartialEq)]
pub struct DirectoryEntry {
    pub page_id: u16,
    pub page_type: PageType,
    pub count: u16,
    pub first_key: TimestampBytes,
    pub last_key: TimestampBytes,
    /// Pre-aggregated XOR fingerprint of all timestamps in this page.
    pub xor_fingerprint: Fingerprint,
}

const DIR_ENTRY_SIZE: usize = 2 + 1 + 2 + 16 + 16 + 12; // 49 bytes

/// The master directory, deserialized from page 0.
#[derive(Clone, Debug)]
pub struct Directory {
    pub entries: heapless::Vec<DirectoryEntry, MAX_DIR_ENTRIES>,
    /// Total count of timestamps across all timestamp pages.
    pub total_timestamp_count: u32,
    /// Next available page_id for allocation.
    pub next_page_id: u16,
}

impl Directory {
    /// Create an empty directory.
    pub fn new() -> Self {
        Directory {
            entries: heapless::Vec::new(),
            total_timestamp_count: 0,
            next_page_id: 1, // page 0 is the directory itself
        }
    }

    /// Serialize the directory into a byte buffer.
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, BufferError> {
        let mut b = Buffer::new(buf);

        // Header: entry_count(2) + total_timestamp_count(4) + next_page_id(2) = 8 bytes
        let count = self.entries.len() as u16;
        b.extend(&count.to_le_bytes())?;
        b.extend(&self.total_timestamp_count.to_le_bytes())?;
        b.extend(&self.next_page_id.to_le_bytes())?;

        // Entries
        for entry in &self.entries {
            b.extend(&entry.page_id.to_le_bytes())?;
            b.push(entry.page_type as u8)?;
            b.extend(&entry.count.to_le_bytes())?;
            b.extend(&entry.first_key)?;
            b.extend(&entry.last_key)?;
            b.extend(&entry.xor_fingerprint)?;
        }

        Ok(b.written_len())
    }

    /// Deserialize a directory from a byte buffer.
    pub fn deserialize(data: &[u8]) -> Result<Self, BufferError> {
        if data.len() < 8 {
            return Err(BufferError::Underflow);
        }

        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let total_timestamp_count = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let next_page_id = u16::from_le_bytes([data[6], data[7]]);

        let mut entries = heapless::Vec::new();
        let mut offset = 8;

        for _ in 0..count {
            if offset + DIR_ENTRY_SIZE > data.len() {
                return Err(BufferError::Underflow);
            }

            let page_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let page_type =
                PageType::from_u8(data[offset + 2]).ok_or(BufferError::IntOutOfRange)?;
            let count =
                u16::from_le_bytes([data[offset + 3], data[offset + 4]]);

            let mut first_key = [0u8; 16];
            first_key.copy_from_slice(&data[offset + 5..offset + 21]);

            let mut last_key = [0u8; 16];
            last_key.copy_from_slice(&data[offset + 21..offset + 37]);

            let mut xor_fingerprint = [0u8; 12];
            xor_fingerprint.copy_from_slice(&data[offset + 37..offset + 49]);

            entries
                .push(DirectoryEntry {
                    page_id,
                    page_type,
                    count,
                    first_key,
                    last_key,
                    xor_fingerprint,
                })
                .map_err(|_| BufferError::Overflow)?;

            offset += DIR_ENTRY_SIZE;
        }

        Ok(Directory {
            entries,
            total_timestamp_count,
            next_page_id,
        })
    }

    /// Find the directory entry whose key range contains the given timestamp.
    /// Only searches timestamp-type pages.
    pub fn find_timestamp_page(&self, ts: &TimestampBytes) -> Option<&DirectoryEntry> {
        self.entries.iter().find(|e| {
            e.page_type == PageType::Timestamp && ts >= &e.first_key && ts <= &e.last_key
        })
    }

    /// Find all timestamp pages whose ranges overlap with [low, high].
    pub fn timestamp_pages_in_range<'a>(
        &'a self,
        low: &'a TimestampBytes,
        high: &'a TimestampBytes,
    ) -> impl Iterator<Item = &'a DirectoryEntry> + 'a {
        self.entries.iter().filter(move |e| {
            e.page_type == PageType::Timestamp && e.last_key >= *low && e.first_key <= *high
        })
    }

    /// Compute the XOR fingerprint for all fully-covered timestamp pages in a range.
    /// Returns (aggregated_fingerprint, partial_pages) where partial_pages are
    /// entries that only partially overlap the range.
    pub fn aggregate_fingerprint(
        &self,
        low: &TimestampBytes,
        high: &TimestampBytes,
    ) -> (Fingerprint, heapless::Vec<u16, 4>) {
        let mut agg = ZERO_FINGERPRINT;
        let mut partials = heapless::Vec::new();

        for entry in &self.entries {
            if entry.page_type != PageType::Timestamp {
                continue;
            }
            if entry.last_key < *low || entry.first_key > *high {
                continue; // No overlap
            }
            if entry.first_key >= *low && entry.last_key <= *high {
                // Fully covered — XOR from directory
                agg = fingerprint_xor(&agg, &entry.xor_fingerprint);
            } else {
                // Partially covered — need to read the page
                let _ = partials.push(entry.page_id);
            }
        }

        (agg, partials)
    }

    /// Allocate a new page ID.
    pub fn alloc_page_id(&mut self) -> u16 {
        let id = self.next_page_id;
        self.next_page_id += 1;
        id
    }

    /// Get total count of all timestamp entries across all pages.
    pub fn timestamp_count(&self) -> u32 {
        self.total_timestamp_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_directory_roundtrip() {
        let dir = Directory::new();
        let mut buf = [0u8; 2048];
        let len = dir.serialize(&mut buf).unwrap();

        let deserialized = Directory::deserialize(&buf[..len]).unwrap();
        assert_eq!(deserialized.entries.len(), 0);
        assert_eq!(deserialized.total_timestamp_count, 0);
        assert_eq!(deserialized.next_page_id, 1);
    }

    #[test]
    fn directory_with_entries_roundtrip() {
        let mut dir = Directory::new();
        dir.total_timestamp_count = 100;
        dir.next_page_id = 5;

        let entry = DirectoryEntry {
            page_id: 1,
            page_type: PageType::Timestamp,
            count: 50,
            first_key: [0u8; 16],
            last_key: {
                let mut k = [0u8; 16];
                k[5] = 100;
                k
            },
            xor_fingerprint: [0xAA; 12],
        };
        dir.entries.push(entry.clone()).unwrap();

        let entry2 = DirectoryEntry {
            page_id: 2,
            page_type: PageType::Timestamp,
            count: 50,
            first_key: {
                let mut k = [0u8; 16];
                k[5] = 101;
                k
            },
            last_key: {
                let mut k = [0u8; 16];
                k[5] = 200;
                k
            },
            xor_fingerprint: [0x55; 12],
        };
        dir.entries.push(entry2.clone()).unwrap();

        let mut buf = [0u8; 2048];
        let len = dir.serialize(&mut buf).unwrap();

        let deserialized = Directory::deserialize(&buf[..len]).unwrap();
        assert_eq!(deserialized.entries.len(), 2);
        assert_eq!(deserialized.total_timestamp_count, 100);
        assert_eq!(deserialized.next_page_id, 5);
        assert_eq!(deserialized.entries[0], entry);
        assert_eq!(deserialized.entries[1], entry2);
    }

    #[test]
    fn find_timestamp_page() {
        let mut dir = Directory::new();
        dir.entries
            .push(DirectoryEntry {
                page_id: 1,
                page_type: PageType::Timestamp,
                count: 10,
                first_key: [0u8; 16],
                last_key: {
                    let mut k = [0u8; 16];
                    k[5] = 50;
                    k
                },
                xor_fingerprint: [0; 12],
            })
            .unwrap();

        let target = {
            let mut k = [0u8; 16];
            k[5] = 25;
            k
        };
        assert!(dir.find_timestamp_page(&target).is_some());

        let outside = {
            let mut k = [0u8; 16];
            k[5] = 100;
            k
        };
        assert!(dir.find_timestamp_page(&outside).is_none());
    }

    #[test]
    fn aggregate_fingerprint_full_coverage() {
        let mut dir = Directory::new();
        dir.entries
            .push(DirectoryEntry {
                page_id: 1,
                page_type: PageType::Timestamp,
                count: 10,
                first_key: [0u8; 16],
                last_key: {
                    let mut k = [0u8; 16];
                    k[5] = 50;
                    k
                },
                xor_fingerprint: [0xAA; 12],
            })
            .unwrap();
        dir.entries
            .push(DirectoryEntry {
                page_id: 2,
                page_type: PageType::Timestamp,
                count: 10,
                first_key: {
                    let mut k = [0u8; 16];
                    k[5] = 51;
                    k
                },
                last_key: {
                    let mut k = [0u8; 16];
                    k[5] = 100;
                    k
                },
                xor_fingerprint: [0x55; 12],
            })
            .unwrap();

        let low = [0u8; 16];
        let high = {
            let mut k = [0u8; 16];
            k[5] = 100;
            k
        };
        let (fp, partials) = dir.aggregate_fingerprint(&low, &high);
        assert_eq!(fp, [0xFF; 12]); // 0xAA ^ 0x55
        assert!(partials.is_empty());
    }

    #[test]
    fn alloc_page_id() {
        let mut dir = Directory::new();
        assert_eq!(dir.alloc_page_id(), 1);
        assert_eq!(dir.alloc_page_id(), 2);
        assert_eq!(dir.alloc_page_id(), 3);
    }
}
