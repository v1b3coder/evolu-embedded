//! Evolu binary protocol codec.
//!
//! Port of `packages/common/src/local-first/Protocol.ts`.
//! All encoding is no_std compatible, operating on `Buffer` cursors.

use crate::types::*;

/// Current protocol version.
pub const PROTOCOL_VERSION: u64 = 1;

// ── ProtocolValueType constants ────────────────────────────────────

/// Values 0-19 are encoded as a single varint (small int optimization).
pub const SMALL_INT_MAX: u64 = 19;

pub const PVT_STRING: u64 = 20;
pub const PVT_NUMBER: u64 = 21;
pub const PVT_NULL: u64 = 22;
pub const PVT_BYTES: u64 = 23;
pub const PVT_NON_NEGATIVE_INT: u64 = 30;
pub const PVT_EMPTY_STRING: u64 = 31;
pub const PVT_BASE64URL: u64 = 32;
pub const PVT_ID: u64 = 33;
pub const PVT_JSON: u64 = 34;
pub const PVT_DATE_ISO_NON_NEG: u64 = 35;
pub const PVT_DATE_ISO_NEG: u64 = 36;

// ── MessageType ────────────────────────────────────────────────────

pub const MESSAGE_TYPE_REQUEST: u8 = 0;
pub const MESSAGE_TYPE_RESPONSE: u8 = 1;
pub const MESSAGE_TYPE_BROADCAST: u8 = 2;

// ── SubscriptionFlags ──────────────────────────────────────────────

pub const SUBSCRIPTION_NONE: u8 = 0;
pub const SUBSCRIPTION_SUBSCRIBE: u8 = 1;
pub const SUBSCRIPTION_UNSUBSCRIBE: u8 = 2;

// ── RangeType ──────────────────────────────────────────────────────

pub const RANGE_TYPE_SKIP: u64 = 0;
pub const RANGE_TYPE_FINGERPRINT: u64 = 1;
pub const RANGE_TYPE_TIMESTAMPS: u64 = 2;

// ── ProtocolErrorCode ──────────────────────────────────────────────

pub const ERROR_NONE: u8 = 0;
pub const ERROR_WRITE_KEY: u8 = 1;
pub const ERROR_WRITE: u8 = 2;
pub const ERROR_QUOTA: u8 = 3;
pub const ERROR_SYNC: u8 = 4;

// ── Varint encoding (Variable-Length Quantity) ──────────────────────

/// Encode a non-negative integer as a variable-length quantity.
/// Uses 7-bit chunks with MSB continuation bit.
pub fn encode_varint(buf: &mut Buffer, value: u64) -> Result<(), BufferError> {
    if value == 0 {
        return buf.push(0);
    }
    let mut remaining = value;
    while remaining > 0 {
        let mut byte = (remaining & 0x7F) as u8;
        remaining >>= 7;
        if remaining > 0 {
            byte |= 0x80;
        }
        buf.push(byte)?;
    }
    Ok(())
}

/// Decode a variable-length quantity. Max 8 bytes (fits JS MAX_SAFE_INTEGER).
pub fn decode_varint(buf: &mut Buffer) -> Result<u64, BufferError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for _ in 0..8 {
        let byte = buf.shift()?;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            // Validate it fits in safe integer range (2^53 - 1)
            if result > 9_007_199_254_740_991 {
                return Err(BufferError::IntOutOfRange);
            }
            return Ok(result);
        }
        shift += 7;
    }
    // All 8 bytes had continuation bit — malformed
    Err(BufferError::IntOutOfRange)
}

// ── String encoding ────────────────────────────────────────────────

/// Encode a UTF-8 string: varint(byte_length) + UTF-8 bytes.
pub fn encode_string(buf: &mut Buffer, s: &str) -> Result<(), BufferError> {
    let bytes = s.as_bytes();
    encode_varint(buf, bytes.len() as u64)?;
    buf.extend(bytes)
}

/// Decode a UTF-8 string. Returns a slice into the buffer's data.
/// Note: the returned slice borrows from the buffer's internal data.
pub fn decode_string_bytes<'a>(buf: &'a mut Buffer) -> Result<&'a [u8], BufferError> {
    let len = decode_varint(buf)? as usize;
    buf.shift_n(len)
}

// ── Flags encoding ─────────────────────────────────────────────────

/// Encode up to 8 boolean flags as a single byte.
pub fn encode_flags(buf: &mut Buffer, flags: &[bool]) -> Result<(), BufferError> {
    let mut byte: u8 = 0;
    for (i, &flag) in flags.iter().enumerate().take(8) {
        if flag {
            byte |= 1 << i;
        }
    }
    buf.push(byte)
}

/// Decode flags from a single byte.
pub fn decode_flags(buf: &mut Buffer, count: u8) -> Result<[bool; 8], BufferError> {
    let byte = buf.shift()?;
    let mut flags = [false; 8];
    for i in 0..(count.min(8) as usize) {
        flags[i] = (byte & (1 << i)) != 0;
    }
    Ok(flags)
}

// ── NodeId encoding ────────────────────────────────────────────────

/// Encode a NodeId as 8 raw bytes.
pub fn encode_node_id(buf: &mut Buffer, node_id: &NodeId) -> Result<(), BufferError> {
    buf.extend(node_id.as_bytes())
}

/// Decode a NodeId from 8 raw bytes.
pub fn decode_node_id(buf: &mut Buffer) -> Result<NodeId, BufferError> {
    let bytes = buf.shift_n(8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(NodeId::from_bytes(arr))
}

// ── Minimal MessagePack for numbers ────────────────────────────────
//
// We only implement the subset needed by the Evolu protocol:
// - positive fixint (0x00-0x7f)
// - negative fixint (0xe0-0xff)
// - int8, uint8, int16, uint16, int32, uint32, int64, uint64
// - float64
//
// This avoids pulling in a full msgpack crate.

/// Encode a number in MessagePack format.
pub fn encode_msgpack_number(buf: &mut Buffer, n: f64) -> Result<(), BufferError> {
    // Check for special float values first
    if n.is_nan() || n.is_infinite() || (n as i64 as f64) != n {
        // float64
        buf.push(0xCB)?;
        buf.extend(&n.to_be_bytes())?;
        return Ok(());
    }

    let i = n as i64;

    // Positive fixint: 0-127
    if i >= 0 && i <= 127 {
        return buf.push(i as u8);
    }

    // Negative fixint: -32 to -1
    if i >= -32 && i < 0 {
        return buf.push(i as u8); // Two's complement, 0xe0-0xff
    }

    // int8: -128 to -33
    if i >= -128 && i < -32 {
        buf.push(0xD0)?;
        return buf.push(i as i8 as u8);
    }

    // uint8: 128-255
    if i >= 128 && i <= 255 {
        buf.push(0xCC)?;
        return buf.push(i as u8);
    }

    // int16: -32768 to -129
    if i >= -32768 && i < -128 {
        buf.push(0xD1)?;
        return buf.extend(&(i as i16).to_be_bytes());
    }

    // uint16: 256-65535
    if i >= 256 && i <= 65535 {
        buf.push(0xCD)?;
        return buf.extend(&(i as u16).to_be_bytes());
    }

    // int32: -2147483648 to -32769
    if i >= -2147483648 && i < -32768 {
        buf.push(0xD2)?;
        return buf.extend(&(i as i32).to_be_bytes());
    }

    // uint32: 65536-4294967295
    if i >= 65536 && i <= 4294967295 {
        buf.push(0xCE)?;
        return buf.extend(&(i as u32).to_be_bytes());
    }

    // For values outside i32/u32 range, msgpackr uses float64 encoding
    // to match JavaScript's number representation. We must do the same
    // for protocol compatibility.
    buf.push(0xCB)?;
    buf.extend(&n.to_be_bytes())
}

/// Decode a MessagePack number.
pub fn decode_msgpack_number(buf: &mut Buffer) -> Result<f64, BufferError> {
    let tag = buf.shift()?;
    match tag {
        // Positive fixint
        0x00..=0x7F => Ok(tag as f64),
        // Negative fixint
        0xE0..=0xFF => Ok((tag as i8) as f64),
        // uint8
        0xCC => Ok(buf.shift()? as f64),
        // uint16
        0xCD => {
            let bytes = buf.shift_n(2)?;
            Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as f64)
        }
        // uint32
        0xCE => {
            let bytes = buf.shift_n(4)?;
            Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64)
        }
        // uint64
        0xCF => {
            let bytes = buf.shift_n(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Ok(u64::from_be_bytes(arr) as f64)
        }
        // int8
        0xD0 => Ok((buf.shift()? as i8) as f64),
        // int16
        0xD1 => {
            let bytes = buf.shift_n(2)?;
            Ok(i16::from_be_bytes([bytes[0], bytes[1]]) as f64)
        }
        // int32
        0xD2 => {
            let bytes = buf.shift_n(4)?;
            Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64)
        }
        // int64
        0xD3 => {
            let bytes = buf.shift_n(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Ok(i64::from_be_bytes(arr) as f64)
        }
        // float32
        0xCA => {
            let bytes = buf.shift_n(4)?;
            Ok(f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64)
        }
        // float64
        0xCB => {
            let bytes = buf.shift_n(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Ok(f64::from_be_bytes(arr))
        }
        _ => Err(BufferError::IntOutOfRange),
    }
}

// ── Length encoding (alias for varint) ─────────────────────────────

/// Encode a length value (alias for encode_varint).
pub fn encode_length(buf: &mut Buffer, len: usize) -> Result<(), BufferError> {
    encode_varint(buf, len as u64)
}

/// Decode a length value (alias for decode_varint).
pub fn decode_length(buf: &mut Buffer) -> Result<usize, BufferError> {
    Ok(decode_varint(buf)? as usize)
}

// ── TimestampsBuffer ───────────────────────────────────────────────
//
// Delta-encoded millis + RLE counters + RLE nodeIds.
// Used for both message timestamps and range upper bounds.

use crate::timestamp::{bytes_to_timestamp, timestamp_to_bytes};
use crate::crypto::padme_padded_length;

/// Encode a list of timestamps using delta + RLE encoding.
///
/// Format:
/// 1. count (varint)
/// 2. delta-encoded millis (each as varint of delta from previous, starting from 0)
/// 3. RLE counters: [value(varint), run_length(varint), ...]
/// 4. RLE nodeIds: [8_bytes, run_length(varint), ...]
pub fn encode_timestamps_buffer(
    buf: &mut Buffer,
    timestamps: &[TimestampBytes],
) -> Result<(), BufferError> {
    encode_varint(buf, timestamps.len() as u64)?;

    if timestamps.is_empty() {
        return Ok(());
    }

    // Delta-encode millis
    let mut prev_millis: u64 = 0;
    for ts_bytes in timestamps {
        let ts = bytes_to_timestamp(ts_bytes);
        let delta = ts.millis.value() - prev_millis;
        encode_varint(buf, delta)?;
        prev_millis = ts.millis.value();
    }

    // RLE-encode counters
    let mut rle_counter_val: Option<u16> = None;
    let mut rle_counter_run: u64 = 0;
    for ts_bytes in timestamps {
        let ts = bytes_to_timestamp(ts_bytes);
        let c = ts.counter.value();
        if Some(c) == rle_counter_val {
            rle_counter_run += 1;
        } else {
            if let Some(v) = rle_counter_val {
                encode_varint(buf, v as u64)?;
                encode_varint(buf, rle_counter_run)?;
            }
            rle_counter_val = Some(c);
            rle_counter_run = 1;
        }
    }
    if let Some(v) = rle_counter_val {
        encode_varint(buf, v as u64)?;
        encode_varint(buf, rle_counter_run)?;
    }

    // RLE-encode nodeIds
    let mut rle_node: Option<NodeId> = None;
    let mut rle_node_run: u64 = 0;
    for ts_bytes in timestamps {
        let ts = bytes_to_timestamp(ts_bytes);
        if Some(ts.node_id) == rle_node {
            rle_node_run += 1;
        } else {
            if let Some(ref n) = rle_node {
                encode_node_id(buf, n)?;
                encode_varint(buf, rle_node_run)?;
            }
            rle_node = Some(ts.node_id);
            rle_node_run = 1;
        }
    }
    if let Some(ref n) = rle_node {
        encode_node_id(buf, n)?;
        encode_varint(buf, rle_node_run)?;
    }

    Ok(())
}

/// Decode a TimestampsBuffer, calling a callback for each decoded timestamp.
/// Returns the number of timestamps decoded.
pub fn decode_timestamps_buffer<F>(
    buf: &mut Buffer,
    mut callback: F,
) -> Result<usize, BufferError>
where
    F: FnMut(TimestampBytes),
{
    let count = decode_varint(buf)? as usize;
    if count == 0 {
        return Ok(0);
    }

    // Decode delta millis
    let mut millis_values: heapless::Vec<u64, 256> = heapless::Vec::new();
    let mut prev_millis: u64 = 0;
    for _ in 0..count {
        let delta = decode_varint(buf)?;
        prev_millis += delta;
        millis_values.push(prev_millis).map_err(|_| BufferError::Overflow)?;
    }

    // Decode RLE counters
    let mut counters: heapless::Vec<u16, 256> = heapless::Vec::new();
    while counters.len() < count {
        let value = decode_varint(buf)? as u16;
        let run = decode_varint(buf)? as usize;
        for _ in 0..run {
            counters.push(value).map_err(|_| BufferError::Overflow)?;
        }
    }

    // Decode RLE nodeIds
    let mut node_ids: heapless::Vec<NodeId, 256> = heapless::Vec::new();
    while node_ids.len() < count {
        let node = decode_node_id(buf)?;
        let run = decode_varint(buf)? as usize;
        for _ in 0..run {
            node_ids.push(node).map_err(|_| BufferError::Overflow)?;
        }
    }

    // Assemble and emit timestamps
    for i in 0..count {
        let ts = Timestamp::new(
            Millis::new(millis_values[i]).map_err(|_| BufferError::IntOutOfRange)?,
            Counter::new(counters[i]),
            node_ids[i],
        );
        callback(timestamp_to_bytes(&ts));
    }

    Ok(count)
}

// ── EncryptedDbChange ──────────────────────────────────────────────

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};

/// Encode and encrypt a DbChange.
///
/// Plaintext format (before encryption):
/// 1. protocolVersion (varint)
/// 2. TimestampBytes (16 bytes) — embedded for tamper detection
/// 3. flags (1 byte): [isInsert, hasIsDelete, isDelete]
/// 4. table name (string)
/// 5. id (16 bytes)
/// 6. column count (varint)
/// 7. For each column: column_name (string) + value encoded as raw bytes
/// 8. PADME padding (zero bytes)
///
/// Wire format: nonce(24) + ciphertext_len(varint) + ciphertext(N+16)
pub fn encode_and_encrypt_db_change(
    encryption_key: &[u8; 32],
    nonce: &[u8; 24],
    timestamp_bytes: &TimestampBytes,
    table: &str,
    id: &IdBytes,
    columns: &[(&str, &[u8])],  // (column_name, pre-encoded_value)
    is_insert: bool,
    is_delete: Option<bool>,
    output: &mut Buffer,
) -> Result<(), BufferError> {
    // Build plaintext in a temporary buffer
    // Max size estimate: we work within the output buffer's remaining space
    let mut plaintext_buf = [0u8; 2048];
    let mut pt = Buffer::new(&mut plaintext_buf);

    // 1. Protocol version
    encode_varint(&mut pt, PROTOCOL_VERSION)?;

    // 2. Timestamp bytes (for tamper detection)
    pt.extend(timestamp_bytes)?;

    // 3. Flags
    encode_flags(
        &mut pt,
        &[is_insert, is_delete.is_some(), is_delete.unwrap_or(false)],
    )?;

    // 4. Table name
    encode_string(&mut pt, table)?;

    // 5. Id
    pt.extend(id.as_bytes())?;

    // 6. Column count + columns
    encode_varint(&mut pt, columns.len() as u64)?;
    for &(col_name, col_value) in columns {
        encode_string(&mut pt, col_name)?;
        pt.extend(col_value)?;
    }

    // 7. PADME padding
    let padded_len = padme_padded_length(pt.written_len() as u32) as usize;
    let padding_size = padded_len - pt.written_len();
    for _ in 0..padding_size {
        pt.push(0)?;
    }

    let plaintext_len = pt.written_len();

    // Encrypt in-place
    let cipher = XChaCha20Poly1305::new(encryption_key.into());
    let xnonce = XNonce::from_slice(nonce);

    // Copy plaintext for encryption
    let mut ct_buf = [0u8; 2048];
    ct_buf[..plaintext_len].copy_from_slice(&plaintext_buf[..plaintext_len]);

    let tag = cipher
        .encrypt_in_place_detached(xnonce, b"", &mut ct_buf[..plaintext_len])
        .map_err(|_| BufferError::Overflow)?;

    // Write wire format: nonce(24) + ciphertext_len(varint) + ciphertext + tag(16)
    output.extend(nonce)?;
    encode_varint(output, (plaintext_len + 16) as u64)?;
    output.extend(&ct_buf[..plaintext_len])?;
    output.extend(&tag)?;

    Ok(())
}

/// Decrypt and decode an EncryptedDbChange, verifying the embedded timestamp.
///
/// Returns the decrypted plaintext (after nonce and length prefix are consumed).
/// The caller is responsible for parsing the DbChange fields from the plaintext.
pub fn decrypt_db_change(
    encryption_key: &[u8; 32],
    encrypted: &[u8],
    expected_timestamp: &TimestampBytes,
) -> Result<DecryptedDbChange, ProtocolError> {
    if encrypted.len() < 24 + 1 + 16 {
        return Err(ProtocolError::InvalidData);
    }

    let nonce = XNonce::from_slice(&encrypted[..24]);

    // Decode ciphertext length
    let mut len_buf = [0u8; 16];
    let remaining = &encrypted[24..];
    let len_bytes = remaining.len().min(10);
    len_buf[..len_bytes].copy_from_slice(&remaining[..len_bytes]);
    let mut len_cursor = Buffer::from_data(&mut len_buf, len_bytes);
    let ct_len = decode_varint(&mut len_cursor).map_err(|_| ProtocolError::InvalidData)? as usize;
    let varint_size = len_bytes - len_cursor.remaining();

    let ct_start = 24 + varint_size;
    if ct_start + ct_len > encrypted.len() {
        return Err(ProtocolError::InvalidData);
    }

    let ciphertext_with_tag = &encrypted[ct_start..ct_start + ct_len];
    if ct_len < 16 {
        return Err(ProtocolError::InvalidData);
    }

    let plaintext_len = ct_len - 16;
    let mut plaintext = [0u8; 2048];
    plaintext[..plaintext_len].copy_from_slice(&ciphertext_with_tag[..plaintext_len]);
    let tag = Tag::from_slice(&ciphertext_with_tag[plaintext_len..]);

    let cipher = XChaCha20Poly1305::new(encryption_key.into());
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut plaintext[..plaintext_len], tag)
        .map_err(|_| ProtocolError::DecryptFailed)?;

    // Parse plaintext
    let mut pt = Buffer::from_data(&mut plaintext, plaintext_len);

    // 1. Protocol version (skip for now)
    let _version = decode_varint(&mut pt).map_err(|_| ProtocolError::InvalidData)?;

    // 2. Verify embedded timestamp
    let embedded_ts = pt.shift_n(16).map_err(|_| ProtocolError::InvalidData)?;
    if embedded_ts != expected_timestamp {
        return Err(ProtocolError::TimestampMismatch);
    }

    // 3. Flags
    let flags = decode_flags(&mut pt, 3).map_err(|_| ProtocolError::InvalidData)?;
    let is_insert = flags[0];
    let has_is_delete = flags[1];
    let is_delete_value = flags[2];

    // 4. Table name
    let table_bytes = decode_string_bytes(&mut pt).map_err(|_| ProtocolError::InvalidData)?;
    let mut table = [0u8; 64];
    let table_len = table_bytes.len().min(64);
    table[..table_len].copy_from_slice(&table_bytes[..table_len]);

    // 5. Id
    let id_bytes = pt.shift_n(16).map_err(|_| ProtocolError::InvalidData)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(id_bytes);

    // 6. Column count
    let column_count = decode_varint(&mut pt).map_err(|_| ProtocolError::InvalidData)? as usize;

    // 7. Parse columns: [name(string), value_bytes...]
    // Capture the first string column value for convenience
    let mut first_string_value = [0u8; 256];
    let mut first_string_len = 0usize;

    for _ in 0..column_count {
        // column name
        let _col_name = decode_string_bytes(&mut pt).map_err(|_| ProtocolError::InvalidData)?;

        // column value: read the type tag
        let value_type = decode_varint(&mut pt).map_err(|_| ProtocolError::InvalidData)?;

        match value_type {
            PVT_STRING => {
                let val_bytes = decode_string_bytes(&mut pt).map_err(|_| ProtocolError::InvalidData)?;
                if first_string_len == 0 {
                    let copy_len = val_bytes.len().min(256);
                    first_string_value[..copy_len].copy_from_slice(&val_bytes[..copy_len]);
                    first_string_len = copy_len;
                }
            }
            PVT_NULL => {}
            PVT_EMPTY_STRING => {
                if first_string_len == 0 {
                    first_string_len = 0; // empty string
                }
            }
            0..=19 => {} // small int, no payload
            PVT_NON_NEGATIVE_INT => { let _ = decode_varint(&mut pt); }
            PVT_NUMBER => { let _ = decode_msgpack_number(&mut pt); }
            PVT_BYTES => {
                let len = decode_length(&mut pt).map_err(|_| ProtocolError::InvalidData)?;
                let _ = pt.shift_n(len);
            }
            PVT_ID => { let _ = pt.shift_n(16); }
            PVT_JSON | PVT_BASE64URL => {
                let len = decode_length(&mut pt).map_err(|_| ProtocolError::InvalidData)?;
                let _ = pt.shift_n(len);
            }
            PVT_DATE_ISO_NON_NEG => { let _ = decode_varint(&mut pt); }
            PVT_DATE_ISO_NEG => { let _ = decode_msgpack_number(&mut pt); }
            _ => { /* unknown type, skip */ break; }
        }
    }

    Ok(DecryptedDbChange {
        is_insert,
        is_delete: if has_is_delete {
            Some(is_delete_value)
        } else {
            None
        },
        table_len,
        table,
        id: IdBytes(id),
        column_count,
        first_string_value,
        first_string_len,
    })
}

/// Result of decrypting a DbChange.
pub struct DecryptedDbChange {
    pub is_insert: bool,
    pub is_delete: Option<bool>,
    pub table_len: usize,
    pub table: [u8; 64],
    pub id: IdBytes,
    pub column_count: usize,
    /// First string column value found (for convenience).
    pub first_string_value: [u8; 256],
    pub first_string_len: usize,
}

impl DecryptedDbChange {
    pub fn table_str(&self) -> &str {
        core::str::from_utf8(&self.table[..self.table_len]).unwrap_or("")
    }

    /// First string column value, if any.
    pub fn first_string(&self) -> Option<&str> {
        if self.first_string_len > 0 {
            core::str::from_utf8(&self.first_string_value[..self.first_string_len]).ok()
        } else {
            None
        }
    }
}

/// Protocol-level errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidData,
    DecryptFailed,
    TimestampMismatch,
    VersionMismatch,
    WriteKeyError,
}

// ── Protocol Message Builder ───────────────────────────────────────

/// Build a protocol message header.
///
/// Format: protocolVersion(varint) + ownerId(16 bytes) + messageType(1 byte)
pub fn encode_protocol_header(
    buf: &mut Buffer,
    owner_id: &[u8; 16],
    message_type: u8,
) -> Result<(), BufferError> {
    encode_varint(buf, PROTOCOL_VERSION)?;
    buf.extend(owner_id)?;
    buf.push(message_type)?;
    Ok(())
}

/// Build a Request header (extends protocol header).
///
/// Adds: hasWriteKey(1 byte) + optional writeKey(16 bytes) + subscriptionFlag(1 byte)
pub fn encode_request_header(
    buf: &mut Buffer,
    owner_id: &[u8; 16],
    write_key: Option<&[u8; 16]>,
    subscription_flag: u8,
) -> Result<(), BufferError> {
    encode_protocol_header(buf, owner_id, MESSAGE_TYPE_REQUEST)?;

    if let Some(wk) = write_key {
        buf.push(1)?; // hasWriteKey = true
        buf.extend(wk)?;
    } else {
        buf.push(0)?; // hasWriteKey = false
    }

    buf.push(subscription_flag)?;
    Ok(())
}

/// Encode the messages count (0 = no messages).
pub fn encode_messages_count(buf: &mut Buffer, count: usize) -> Result<(), BufferError> {
    encode_varint(buf, count as u64)
}

/// Encode the ranges count.
pub fn encode_ranges_count(buf: &mut Buffer, count: usize) -> Result<(), BufferError> {
    encode_varint(buf, count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Varint tests ────────────────────────────────────────────

    #[test]
    fn varint_test_vectors() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0]),
            (1, &[1]),
            (127, &[127]),
            (128, &[128, 1]),
            (129, &[129, 1]),
            (255, &[255, 1]),
            (16383, &[255, 127]),
            (16384, &[128, 128, 1]),
            (32767, &[255, 255, 1]),
            (2097151, &[255, 255, 127]),
            (2097152, &[128, 128, 128, 1]),
            (268435455, &[255, 255, 255, 127]),
            (9007199254740991, &[255, 255, 255, 255, 255, 255, 255, 15]), // MAX_SAFE_INTEGER
            (9007199254740990, &[254, 255, 255, 255, 255, 255, 255, 15]), // MAX_SAFE_INTEGER - 1
        ];

        for &(value, expected) in cases {
            let mut backing = [0u8; 16];
            let mut buf = Buffer::new(&mut backing);
            encode_varint(&mut buf, value).unwrap();
            assert_eq!(buf.written(), expected, "encode({}) failed", value);

            let mut read_buf = [0u8; 16];
            read_buf[..expected.len()].copy_from_slice(expected);
            let mut buf2 = Buffer::from_data(&mut read_buf, expected.len());
            assert_eq!(decode_varint(&mut buf2).unwrap(), value, "decode({}) failed", value);
        }
    }

    #[test]
    fn varint_overflow_rejected() {
        // 8 bytes all with continuation bit = malformed
        let mut data = [0xFFu8; 8];
        let mut buf = Buffer::from_data(&mut data, 8);
        assert!(decode_varint(&mut buf).is_err());
    }

    #[test]
    fn varint_truncated_rejected() {
        let mut data = [128u8]; // continuation bit set but no next byte
        let mut buf = Buffer::from_data(&mut data, 1);
        assert!(decode_varint(&mut buf).is_err());
    }

    // ── String tests ────────────────────────────────────────────

    #[test]
    fn string_hello_world() {
        let expected: &[u8] = &[13, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33];

        let mut backing = [0u8; 64];
        let mut buf = Buffer::new(&mut backing);
        encode_string(&mut buf, "Hello, world!").unwrap();
        assert_eq!(buf.written(), expected);
    }

    #[test]
    fn string_roundtrip() {
        let binding = "a".repeat(200);
        let test_strings = &["", "Hello", "日本語", binding.as_str()];
        for &s in test_strings {
            let mut backing = [0u8; 512];
            let mut buf = Buffer::new(&mut backing);
            encode_string(&mut buf, s).unwrap();
            let len = buf.written_len();

            let mut read_backing = [0u8; 512];
            read_backing[..len].copy_from_slice(buf.written());
            let mut buf2 = Buffer::from_data(&mut read_backing, len);
            let decoded = decode_string_bytes(&mut buf2).unwrap();
            assert_eq!(core::str::from_utf8(decoded).unwrap(), s);
        }
    }

    // ── Flags tests ─────────────────────────────────────────────

    #[test]
    fn flags_test_vectors() {
        let cases: &[(&[bool], u8)] = &[
            (&[true], 1),
            (&[false], 0),
            (&[true, false], 1),
            (&[false, true], 2),
            (&[true, true], 3),
            (&[true, false, true, false, true], 0b10101),
            (&[true, true, true, true, true, true, true, true], 0xFF),
        ];

        for &(flags, expected_byte) in cases {
            let mut backing = [0u8; 1];
            let mut buf = Buffer::new(&mut backing);
            encode_flags(&mut buf, flags).unwrap();
            assert_eq!(buf.written()[0], expected_byte);

            let mut read_backing = [expected_byte];
            let mut buf2 = Buffer::from_data(&mut read_backing, 1);
            let decoded = decode_flags(&mut buf2, flags.len() as u8).unwrap();
            for (i, &flag) in flags.iter().enumerate() {
                assert_eq!(decoded[i], flag, "flag {} mismatch", i);
            }
        }
    }

    // ── NodeId tests ────────────────────────────────────────────

    #[test]
    fn node_id_roundtrip() {
        let node = NodeId::from_hex("4febdfb5d0782bfa").unwrap();
        let mut backing = [0u8; 8];
        let mut buf = Buffer::new(&mut backing);
        encode_node_id(&mut buf, &node).unwrap();

        let mut read_backing = [0u8; 8];
        read_backing.copy_from_slice(buf.written());
        let mut buf2 = Buffer::from_data(&mut read_backing, 8);
        let decoded = decode_node_id(&mut buf2).unwrap();
        assert_eq!(decoded, node);
    }

    // ── MessagePack number tests ────────────────────────────────

    #[test]
    fn msgpack_number_test_vectors() {
        // From Protocol.test.ts: encodeNumber/decodeNumber test
        // The expected concatenated output for [0, 42, -123, 3.14159, MAX_SAFE, MIN_SAFE, Inf, -Inf, NaN]
        let expected: &[u8] = &[
            0, 42, 208, 133, 203, 64, 9, 33, 249, 240, 27, 134, 110, 203, 67, 63, 255, 255, 255,
            255, 255, 255, 203, 195, 63, 255, 255, 255, 255, 255, 255, 203, 127, 240, 0, 0, 0, 0,
            0, 0, 203, 255, 240, 0, 0, 0, 0, 0, 0, 203, 127, 248, 0, 0, 0, 0, 0, 0,
        ];

        let values: &[f64] = &[
            0.0,
            42.0,
            -123.0,
            3.14159,
            9007199254740991.0, // MAX_SAFE_INTEGER
            -9007199254740991.0, // MIN_SAFE_INTEGER
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];

        let mut backing = [0u8; 128];
        let mut buf = Buffer::new(&mut backing);
        for &v in values {
            encode_msgpack_number(&mut buf, v).unwrap();
        }
        assert_eq!(buf.written(), expected);

        // Decode each individually
        for &v in values {
            let mut enc_backing = [0u8; 16];
            let mut enc_buf = Buffer::new(&mut enc_backing);
            encode_msgpack_number(&mut enc_buf, v).unwrap();
            let len = enc_buf.written_len();

            let mut dec_backing = [0u8; 16];
            dec_backing[..len].copy_from_slice(enc_buf.written());
            let mut dec_buf = Buffer::from_data(&mut dec_backing, len);
            let decoded = decode_msgpack_number(&mut dec_buf).unwrap();

            if v.is_nan() {
                assert!(decoded.is_nan(), "NaN roundtrip failed");
            } else {
                assert_eq!(decoded, v, "roundtrip failed for {}", v);
            }
            assert_eq!(dec_buf.remaining(), 0, "leftover bytes for {}", v);
        }
    }

    // ── Length tests ────────────────────────────────────────────

    #[test]
    fn length_encoding() {
        let mut backing = [0u8; 16];
        let mut buf = Buffer::new(&mut backing);
        encode_length(&mut buf, 0).unwrap();
        assert_eq!(decode_varint(&mut buf).unwrap(), 0);

        buf.reset();
        encode_length(&mut buf, 3).unwrap();
        let len = buf.written_len();
        let mut read = [0u8; 16];
        read[..len].copy_from_slice(buf.written());
        let mut buf2 = Buffer::from_data(&mut read, len);
        assert_eq!(decode_length(&mut buf2).unwrap(), 3);
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    // ── TimestampsBuffer tests ──────────────────────────────────

    #[test]
    fn timestamps_buffer_empty() {
        let mut backing = [0u8; 64];
        let mut buf = Buffer::new(&mut backing);
        encode_timestamps_buffer(&mut buf, &[]).unwrap();
        assert_eq!(buf.written(), &[0]); // just the count=0

        let mut read = [0u8; 1];
        read[0] = 0;
        let mut buf2 = Buffer::from_data(&mut read, 1);
        let count = decode_timestamps_buffer(&mut buf2, |_| {}).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn timestamps_buffer_roundtrip() {
        use crate::timestamp::timestamp_to_bytes;

        let timestamps: Vec<TimestampBytes> = vec![
            timestamp_to_bytes(&Timestamp::new(
                Millis::new(1000).unwrap(),
                Counter::new(0),
                NodeId::from_hex("68a2a7bf3f85a096").unwrap(),
            )),
            timestamp_to_bytes(&Timestamp::new(
                Millis::new(2000).unwrap(),
                Counter::new(0),
                NodeId::from_hex("68a2a7bf3f85a096").unwrap(),
            )),
            timestamp_to_bytes(&Timestamp::new(
                Millis::new(3000).unwrap(),
                Counter::new(1),
                NodeId::from_hex("99c99028d6636a91").unwrap(),
            )),
        ];

        let mut backing = [0u8; 256];
        let mut buf = Buffer::new(&mut backing);
        encode_timestamps_buffer(&mut buf, &timestamps).unwrap();
        let enc_len = buf.written_len();

        let mut read = [0u8; 256];
        read[..enc_len].copy_from_slice(buf.written());
        let mut buf2 = Buffer::from_data(&mut read, enc_len);

        let mut decoded = Vec::new();
        decode_timestamps_buffer(&mut buf2, |ts| decoded.push(ts)).unwrap();

        assert_eq!(decoded, timestamps);
    }

    #[test]
    fn timestamps_buffer_rle_efficiency() {
        use crate::timestamp::timestamp_to_bytes;

        // 10 timestamps with same counter and nodeId → RLE compresses well
        let node = NodeId::from_hex("68a2a7bf3f85a096").unwrap();
        let timestamps: Vec<TimestampBytes> = (0..10)
            .map(|i| {
                timestamp_to_bytes(&Timestamp::new(
                    Millis::new(i * 1000).unwrap(),
                    Counter::new(0),
                    node,
                ))
            })
            .collect();

        let mut backing = [0u8; 256];
        let mut buf = Buffer::new(&mut backing);
        encode_timestamps_buffer(&mut buf, &timestamps).unwrap();

        // Counter RLE: 1 value + 1 run = 2 varints
        // NodeId RLE: 8 bytes + 1 varint
        // Should be much smaller than 10 * 16 = 160 bytes
        assert!(
            buf.written_len() < 60,
            "RLE should compress: got {} bytes",
            buf.written_len()
        );
    }

    // ── EncryptedDbChange tests ─────────────────────────────────

    #[test]
    fn encrypt_decrypt_db_change_roundtrip() {
        let key: [u8; 32] = [
            0x5b, 0xf1, 0x4c, 0x7d, 0x9e, 0x75, 0xe3, 0x7d, 0xe6, 0x32, 0x57, 0xcc, 0xa7, 0x50,
            0x38, 0xe9, 0xec, 0x20, 0x77, 0x72, 0x03, 0x85, 0x0b, 0x72, 0xf5, 0x4c, 0xe6, 0x08,
            0x7b, 0xbb, 0x9e, 0x73,
        ];
        let mut nonce = [0u8; 24];
        nonce[0] = 0x42;

        let ts = crate::timestamp::timestamp_to_bytes(&Timestamp::new(
            Millis::new(1000).unwrap(),
            Counter::new(0),
            NodeId::from_hex("4febdfb5d0782bfa").unwrap(),
        ));

        let id = IdBytes([0x51, 0x2f, 0xbf, 0x6d, 0x07, 0x41, 0xe6, 0x0b,
                          0x38, 0x3a, 0x6c, 0xb2, 0xfc, 0xfa, 0xf7, 0xca]);

        // Pre-encode column value as a simple string
        let mut val_buf = [0u8; 64];
        let mut val_cursor = Buffer::new(&mut val_buf);
        encode_varint(&mut val_cursor, PVT_STRING as u64).unwrap();
        encode_string(&mut val_cursor, "Victoria").unwrap();
        let val_len = val_cursor.written_len();
        let val_bytes = &val_buf[..val_len];

        let mut out_backing = [0u8; 4096];
        let mut out = Buffer::new(&mut out_backing);

        encode_and_encrypt_db_change(
            &key,
            &nonce,
            &ts,
            "employee",
            &id,
            &[("name", val_bytes)],
            true,
            None,
            &mut out,
        )
        .unwrap();

        // Now decrypt
        let encrypted = out.written().to_vec();
        let result = decrypt_db_change(&key, &encrypted, &ts).unwrap();

        assert!(result.is_insert);
        assert_eq!(result.is_delete, None);
        assert_eq!(result.table_str(), "employee");
        assert_eq!(result.id, id);
        assert_eq!(result.column_count, 1);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key: [u8; 32] = [0x42; 32];
        let wrong_key: [u8; 32] = [0xFF; 32];
        let nonce = [0u8; 24];

        let ts = [0u8; 16];
        let id = IdBytes([0; 16]);

        let mut out_backing = [0u8; 4096];
        let mut out = Buffer::new(&mut out_backing);

        encode_and_encrypt_db_change(
            &key, &nonce, &ts, "t", &id, &[], true, None, &mut out,
        )
        .unwrap();

        let encrypted = out.written().to_vec();
        assert!(matches!(
            decrypt_db_change(&wrong_key, &encrypted, &ts),
            Err(ProtocolError::DecryptFailed)
        ));
    }

    #[test]
    fn decrypt_wrong_timestamp_fails() {
        let key: [u8; 32] = [0x42; 32];
        let nonce = [0u8; 24];

        let ts = [0u8; 16];
        let wrong_ts = {
            let mut t = [0u8; 16];
            t[5] = 1;
            t
        };
        let id = IdBytes([0; 16]);

        let mut out_backing = [0u8; 4096];
        let mut out = Buffer::new(&mut out_backing);

        encode_and_encrypt_db_change(
            &key, &nonce, &ts, "t", &id, &[], true, None, &mut out,
        )
        .unwrap();

        let encrypted = out.written().to_vec();
        assert!(matches!(
            decrypt_db_change(&key, &encrypted, &wrong_ts),
            Err(ProtocolError::TimestampMismatch)
        ));
    }

    // ── Protocol header tests ───────────────────────────────────

    #[test]
    fn protocol_header_empty_request() {
        // From Protocol.test.ts: empty DB message
        // Expected: [1, 74, 214, 239, 117, 51, 241, 147, 205, 51, 209, 195, 85, 192, 50, 96, 234, 0, 0, 0, 0]
        let owner_id: [u8; 16] = [
            0x4a, 0xd6, 0xef, 0x75, 0x33, 0xf1, 0x93, 0xcd, 0x33, 0xd1, 0xc3, 0x55, 0xc0, 0x32,
            0x60, 0xea,
        ];

        let mut backing = [0u8; 64];
        let mut buf = Buffer::new(&mut backing);

        // Header: version(1) + ownerId(16) + messageType(0=Request)
        encode_request_header(&mut buf, &owner_id, None, SUBSCRIPTION_NONE).unwrap();
        // Messages count: 0
        encode_messages_count(&mut buf, 0).unwrap();

        let expected_header: &[u8] = &[
            1, 74, 214, 239, 117, 51, 241, 147, 205, 51, 209, 195, 85, 192, 50, 96, 234, 0, 0,
            0, 0,
        ];
        assert_eq!(buf.written(), expected_header);
    }
}
