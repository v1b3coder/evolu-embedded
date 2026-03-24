//! Foundation types for the Evolu embedded port.
//!
//! All types are designed for no_std / zero-allocation usage on embedded.

use core::cmp::Ordering;
use core::fmt;

// ── Timestamp components ───────────────────────────────────────────

/// Milliseconds since Unix epoch, stored in 6 bytes (max ~year 8889).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Millis(u64);

/// Maximum value representable in 6 bytes minus 1 (reserved for infinity).
pub const MAX_MILLIS: u64 = 281_474_976_710_654;
pub const MIN_MILLIS: u64 = 0;

impl Millis {
    pub fn new(value: u64) -> Result<Self, TimestampError> {
        if value > MAX_MILLIS {
            Err(TimestampError::TimeOutOfRange)
        } else {
            Ok(Millis(value))
        }
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

/// Logical counter within a millisecond (0..=65535).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Counter(u16);

pub const MAX_COUNTER: u16 = 65_535;
pub const MIN_COUNTER: u16 = 0;

impl Counter {
    pub fn new(value: u16) -> Self {
        Counter(value)
    }

    pub fn value(self) -> u16 {
        self.0
    }

    pub fn increment(self) -> Result<Self, TimestampError> {
        if self.0 >= MAX_COUNTER {
            Err(TimestampError::CounterOverflow)
        } else {
            Ok(Counter(self.0 + 1))
        }
    }
}

/// Unique device identifier (8 bytes / 64 bits).
/// In TypeScript this is a 16-character lowercase hex string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 8]);

impl NodeId {
    pub const MIN: NodeId = NodeId([0u8; 8]);
    pub const MAX: NodeId = NodeId([0xff; 8]);

    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        NodeId(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Parse from 16-character lowercase hex string.
    /// Rejects uppercase hex to match TypeScript's `/^[a-f0-9]{16}$/` regex.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 16 {
            return None;
        }
        // Validate all chars are lowercase hex
        if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut bytes = [0u8; 8];
        for i in 0..8 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(NodeId(bytes))
    }

    /// Format as 16-character lowercase hex string into a buffer.
    pub fn to_hex<'a>(&self, buf: &'a mut [u8; 16]) -> &'a str {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for i in 0..8 {
            buf[i * 2] = HEX[(self.0[i] >> 4) as usize];
            buf[i * 2 + 1] = HEX[(self.0[i] & 0x0f) as usize];
        }
        // SAFETY: we only wrote ASCII hex chars
        unsafe { core::str::from_utf8_unchecked(&buf[..]) }
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 16];
        let hex = self.to_hex(&mut buf);
        f.debug_tuple("NodeId").field(&hex).finish()
    }
}

// ── Timestamp ──────────────────────────────────────────────────────

/// Hybrid Logical Clock timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub millis: Millis,
    pub counter: Counter,
    pub node_id: NodeId,
}

impl Timestamp {
    pub fn new(millis: Millis, counter: Counter, node_id: NodeId) -> Self {
        Timestamp { millis, counter, node_id }
    }

    pub fn zero() -> Self {
        Timestamp {
            millis: Millis(0),
            counter: Counter(0),
            node_id: NodeId::MIN,
        }
    }
}

/// 16-byte sortable binary representation of a Timestamp.
pub type TimestampBytes = [u8; 16];

pub const TIMESTAMP_BYTES_LEN: usize = 16;

// ── Fingerprint ────────────────────────────────────────────────────

/// SHA-256 truncated to 12 bytes, used for RBSR range comparison.
pub type Fingerprint = [u8; 12];

pub const FINGERPRINT_SIZE: usize = 12;

/// XOR two fingerprints (for range aggregation).
pub fn fingerprint_xor(a: &Fingerprint, b: &Fingerprint) -> Fingerprint {
    let mut result = [0u8; 12];
    for i in 0..12 {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub const ZERO_FINGERPRINT: Fingerprint = [0u8; 12];

// ── Id ─────────────────────────────────────────────────────────────

/// Row identifier: 16 bytes (binary form of the 22-char base64url Id in TS).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdBytes(pub [u8; 16]);

impl IdBytes {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        IdBytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for IdBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdBytes(")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimestampError {
    /// Clock drift exceeds maximum allowed.
    Drift { next: u64, now: u64 },
    /// Counter would exceed 65535.
    CounterOverflow,
    /// Physical clock value out of representable range.
    TimeOutOfRange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BufferError {
    /// Not enough data remaining to read.
    Underflow,
    /// Not enough space to write.
    Overflow,
    /// Invalid UTF-8 in decoded string.
    InvalidUtf8,
    /// Decoded integer out of range.
    IntOutOfRange,
}

// ── Buffer ─────────────────────────────────────────────────────────

/// Zero-allocation cursor over a mutable byte slice.
/// Used for both reading and writing protocol data within the 2KB page buffer.
pub struct Buffer<'a> {
    data: &'a mut [u8],
    /// Write position (appending new data).
    write_pos: usize,
    /// Read position (consuming data).
    read_pos: usize,
}

impl<'a> Buffer<'a> {
    /// Create a new empty buffer for writing.
    pub fn new(data: &'a mut [u8]) -> Self {
        Buffer { data, write_pos: 0, read_pos: 0 }
    }

    /// Create a buffer wrapping existing data for reading.
    pub fn from_data(data: &'a mut [u8], len: usize) -> Self {
        Buffer { data, write_pos: len, read_pos: 0 }
    }

    /// Remaining bytes available for reading.
    pub fn remaining(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Total bytes written.
    pub fn written_len(&self) -> usize {
        self.write_pos
    }

    /// Get a slice of all written data.
    pub fn written(&self) -> &[u8] {
        &self.data[..self.write_pos]
    }

    /// Append a single byte.
    pub fn push(&mut self, byte: u8) -> Result<(), BufferError> {
        if self.write_pos >= self.data.len() {
            return Err(BufferError::Overflow);
        }
        self.data[self.write_pos] = byte;
        self.write_pos += 1;
        Ok(())
    }

    /// Append a slice of bytes.
    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        let end = self.write_pos + bytes.len();
        if end > self.data.len() {
            return Err(BufferError::Overflow);
        }
        self.data[self.write_pos..end].copy_from_slice(bytes);
        self.write_pos = end;
        Ok(())
    }

    /// Read and consume a single byte.
    pub fn shift(&mut self) -> Result<u8, BufferError> {
        if self.read_pos >= self.write_pos {
            return Err(BufferError::Underflow);
        }
        let byte = self.data[self.read_pos];
        self.read_pos += 1;
        Ok(byte)
    }

    /// Read and consume N bytes, returning a slice.
    pub fn shift_n(&mut self, n: usize) -> Result<&[u8], BufferError> {
        let end = self.read_pos + n;
        if end > self.write_pos {
            return Err(BufferError::Underflow);
        }
        let slice = &self.data[self.read_pos..end];
        self.read_pos = end;
        Ok(slice)
    }

    /// Peek at the next byte without consuming.
    pub fn peek(&self) -> Result<u8, BufferError> {
        if self.read_pos >= self.write_pos {
            return Err(BufferError::Underflow);
        }
        Ok(self.data[self.read_pos])
    }

    /// Reset read and write positions.
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }

    /// Capacity of the underlying buffer.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }
}

// ── Order helper ───────────────────────────────────────────────────

/// Lexicographic comparison of byte slices (used for TimestampBytes ordering).
pub fn order_bytes(a: &[u8], b: &[u8]) -> Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millis_validation() {
        assert!(Millis::new(0).is_ok());
        assert!(Millis::new(MAX_MILLIS).is_ok());
        assert!(Millis::new(MAX_MILLIS + 1).is_err());
    }

    #[test]
    fn counter_increment() {
        let c = Counter::new(0);
        assert_eq!(c.increment().unwrap().value(), 1);

        let c = Counter::new(MAX_COUNTER);
        assert!(c.increment().is_err());
    }

    #[test]
    fn node_id_hex_roundtrip() {
        let hex = "4febdfb5d0782bfa";
        let node = NodeId::from_hex(hex).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(node.to_hex(&mut buf), hex);
    }

    #[test]
    fn node_id_validation() {
        assert!(NodeId::from_hex("").is_none());
        assert!(NodeId::from_hex("0000000000000000").is_some());
        assert!(NodeId::from_hex("aaaaaaaaaaaaaaaa").is_some());
        // Uppercase invalid
        assert!(NodeId::from_hex("Aaaaaaaaaaaaaaaa").is_none());
        // Too long
        assert!(NodeId::from_hex("aaaaaaaaaaaaaaaaa").is_none());
    }

    #[test]
    fn buffer_read_write() {
        let mut backing = [0u8; 64];
        let mut buf = Buffer::new(&mut backing);

        buf.push(0x42).unwrap();
        buf.extend(&[1, 2, 3]).unwrap();
        assert_eq!(buf.written_len(), 4);
        assert_eq!(buf.written(), &[0x42, 1, 2, 3]);

        assert_eq!(buf.shift().unwrap(), 0x42);
        assert_eq!(buf.shift_n(3).unwrap(), &[1, 2, 3]);
        assert_eq!(buf.remaining(), 0);
        assert!(buf.shift().is_err());
    }

    #[test]
    fn fingerprint_xor_works() {
        let a = [0xFF; 12];
        let b = [0xFF; 12];
        assert_eq!(fingerprint_xor(&a, &b), ZERO_FINGERPRINT);

        let c = [0xAA; 12];
        let d = [0x55; 12];
        assert_eq!(fingerprint_xor(&c, &d), [0xFF; 12]);
    }
}
