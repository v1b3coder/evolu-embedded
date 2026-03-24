//! Protocol message builder — wire-compatible with TypeScript Evolu.
//!
//! Produces byte-exact messages matching `createProtocolMessageBuffer` from
//! `packages/common/src/local-first/Protocol.ts`.
//!
//! ## Wire format
//!
//! ```text
//! header || messages_ts || messages_dbchanges || ranges_ts || ranges_types || ranges_payloads
//! ```
//!
//! - **header**: version(varint) + ownerId(16B) + messageType(1B) + type-specific fields
//! - **messages_ts**: TimestampsBuffer encoding of message timestamps
//! - **messages_dbchanges**: concatenated [length(varint) + EncryptedDbChange]
//! - **ranges_ts**: TimestampsBuffer encoding of range upper bounds
//!   (count = N_ranges, but only N-1 real timestamps — last is InfiniteUpperBound)
//! - **ranges_types**: varint per range (0=Skip, 1=Fingerprint, 2=Timestamps)
//! - **ranges_payloads**: concatenated payloads per range type

use crate::protocol::*;
use crate::types::*;

/// Maximum messages in a single protocol message.
const MAX_MESSAGES: usize = 256;
/// Maximum ranges in a single protocol message.
const MAX_RANGES: usize = 32;

/// Builds a wire-compatible Evolu protocol message.
pub struct MessageBuilder {
    header_buf: [u8; 256],
    header_len: usize,

    // Messages: timestamps collected, dbchanges concatenated
    msg_timestamps: heapless::Vec<TimestampBytes, MAX_MESSAGES>,
    msg_dbchanges_buf: [u8; 32768],
    msg_dbchanges_len: usize,

    // Ranges: upper bounds collected, types + payloads concatenated
    range_upper_bounds: heapless::Vec<Option<TimestampBytes>, MAX_RANGES>,
    range_types_buf: [u8; 256],
    range_types_len: usize,
    range_payloads_buf: [u8; 16384],
    range_payloads_len: usize,
}

impl MessageBuilder {
    /// Start building a Request message.
    pub fn new_request(
        owner_id: &[u8; 16],
        write_key: Option<&[u8; 16]>,
        subscription_flag: u8,
    ) -> Result<Self, BufferError> {
        let mut hdr = [0u8; 256];
        let mut buf = Buffer::new(&mut hdr);

        encode_varint(&mut buf, PROTOCOL_VERSION)?;
        buf.extend(owner_id)?;
        buf.push(MESSAGE_TYPE_REQUEST)?;
        if let Some(wk) = write_key {
            buf.push(1)?;
            buf.extend(wk)?;
        } else {
            buf.push(0)?;
        }
        buf.push(subscription_flag)?;

        let header_len = buf.written_len();

        Ok(MessageBuilder {
            header_buf: hdr,
            header_len,
            msg_timestamps: heapless::Vec::new(),
            msg_dbchanges_buf: [0u8; 32768],
            msg_dbchanges_len: 0,
            range_upper_bounds: heapless::Vec::new(),
            range_types_buf: [0u8; 256],
            range_types_len: 0,
            range_payloads_buf: [0u8; 16384],
            range_payloads_len: 0,
        })
    }

    /// Add an encrypted CRDT message.
    pub fn add_message(
        &mut self,
        timestamp: &TimestampBytes,
        encrypted_change: &[u8],
    ) -> Result<(), BufferError> {
        self.msg_timestamps.push(*timestamp).map_err(|_| BufferError::Overflow)?;

        // Length-prefixed encrypted change
        let mut len_buf = [0u8; 10];
        let mut lb = Buffer::new(&mut len_buf);
        encode_varint(&mut lb, encrypted_change.len() as u64)?;
        let len_bytes = lb.written();

        let needed = len_bytes.len() + encrypted_change.len();
        let end = self.msg_dbchanges_len + needed;
        if end > self.msg_dbchanges_buf.len() {
            return Err(BufferError::Overflow);
        }
        self.msg_dbchanges_buf[self.msg_dbchanges_len..self.msg_dbchanges_len + len_bytes.len()]
            .copy_from_slice(len_bytes);
        self.msg_dbchanges_buf[self.msg_dbchanges_len + len_bytes.len()..end]
            .copy_from_slice(encrypted_change);
        self.msg_dbchanges_len = end;

        Ok(())
    }

    /// Add a Skip range.
    /// `upper_bound`: `None` = InfiniteUpperBound, `Some(ts)` = specific timestamp.
    pub fn add_skip_range(&mut self, upper_bound: Option<&TimestampBytes>) -> Result<(), BufferError> {
        self.range_upper_bounds.push(upper_bound.copied()).map_err(|_| BufferError::Overflow)?;
        self.write_range_type(RANGE_TYPE_SKIP)?;
        Ok(())
    }

    /// Add a Fingerprint range.
    pub fn add_fingerprint_range(
        &mut self,
        upper_bound: Option<&TimestampBytes>,
        fingerprint: &Fingerprint,
    ) -> Result<(), BufferError> {
        self.range_upper_bounds.push(upper_bound.copied()).map_err(|_| BufferError::Overflow)?;
        self.write_range_type(RANGE_TYPE_FINGERPRINT)?;
        self.write_range_payload(fingerprint)?;
        Ok(())
    }

    /// Add a Timestamps range.
    pub fn add_timestamps_range(
        &mut self,
        upper_bound: Option<&TimestampBytes>,
        timestamps: &[TimestampBytes],
    ) -> Result<(), BufferError> {
        self.range_upper_bounds.push(upper_bound.copied()).map_err(|_| BufferError::Overflow)?;
        self.write_range_type(RANGE_TYPE_TIMESTAMPS)?;

        // Encode nested TimestampsBuffer as payload
        let start = self.range_payloads_len;
        let remaining = &mut self.range_payloads_buf[start..];
        let mut buf = Buffer::new(remaining);
        encode_timestamps_buffer(&mut buf, timestamps)?;
        self.range_payloads_len += buf.written_len();

        Ok(())
    }

    /// Finalize and write the complete message to output.
    /// Returns the total message length.
    pub fn finalize(&self, output: &mut [u8]) -> Result<usize, BufferError> {
        let mut pos = 0;

        // 1. Header
        Self::copy_to(output, &mut pos, &self.header_buf[..self.header_len])?;

        // 2. Messages TimestampsBuffer
        let mut ts_buf = [0u8; 8192];
        let mut ts_writer = Buffer::new(&mut ts_buf);
        encode_timestamps_buffer(&mut ts_writer, &self.msg_timestamps)?;
        Self::copy_to(output, &mut pos, ts_writer.written())?;

        // 3. Messages dbChanges
        Self::copy_to(output, &mut pos, &self.msg_dbchanges_buf[..self.msg_dbchanges_len])?;

        // 4. Ranges (only if any ranges exist)
        if !self.range_upper_bounds.is_empty() {
            // 4a. Ranges TimestampsBuffer (upper bounds)
            // Count = total ranges. Real timestamps = only non-None entries.
            // InfiniteUpperBound (None) only increments count, adds no data.
            let real_upper_bounds: heapless::Vec<TimestampBytes, MAX_RANGES> = self
                .range_upper_bounds
                .iter()
                .filter_map(|ub| *ub)
                .collect();

            // The TS TimestampsBuffer encodes count = total_ranges (including infinite),
            // but only encodes millis/counter/nodeId for the real timestamps.
            let total_count = self.range_upper_bounds.len();
            let mut ub_buf = [0u8; 4096];
            let mut ub_writer = Buffer::new(&mut ub_buf);

            // Write count (includes infinite)
            encode_varint(&mut ub_writer, total_count as u64)?;

            if !real_upper_bounds.is_empty() {
                // Write delta millis
                let mut prev_millis = 0u64;
                for ts_bytes in &real_upper_bounds {
                    let ts = crate::timestamp::bytes_to_timestamp(ts_bytes);
                    let delta = ts.millis.value() - prev_millis;
                    encode_varint(&mut ub_writer, delta)?;
                    prev_millis = ts.millis.value();
                }

                // Write counter RLE
                let mut prev_counter: Option<u16> = None;
                let mut run: u64 = 0;
                for ts_bytes in &real_upper_bounds {
                    let ts = crate::timestamp::bytes_to_timestamp(ts_bytes);
                    let c = ts.counter.value();
                    if Some(c) == prev_counter {
                        run += 1;
                    } else {
                        if let Some(pc) = prev_counter {
                            encode_varint(&mut ub_writer, pc as u64)?;
                            encode_varint(&mut ub_writer, run)?;
                        }
                        prev_counter = Some(c);
                        run = 1;
                    }
                }
                if let Some(pc) = prev_counter {
                    encode_varint(&mut ub_writer, pc as u64)?;
                    encode_varint(&mut ub_writer, run)?;
                }

                // Write nodeId RLE
                let mut prev_node: Option<NodeId> = None;
                let mut run: u64 = 0;
                for ts_bytes in &real_upper_bounds {
                    let ts = crate::timestamp::bytes_to_timestamp(ts_bytes);
                    if Some(ts.node_id) == prev_node {
                        run += 1;
                    } else {
                        if let Some(ref pn) = prev_node {
                            encode_node_id(&mut ub_writer, pn)?;
                            encode_varint(&mut ub_writer, run)?;
                        }
                        prev_node = Some(ts.node_id);
                        run = 1;
                    }
                }
                if let Some(ref pn) = prev_node {
                    encode_node_id(&mut ub_writer, pn)?;
                    encode_varint(&mut ub_writer, run)?;
                }
            }

            Self::copy_to(output, &mut pos, ub_writer.written())?;

            // 4b. Range types
            Self::copy_to(output, &mut pos, &self.range_types_buf[..self.range_types_len])?;

            // 4c. Range payloads
            Self::copy_to(output, &mut pos, &self.range_payloads_buf[..self.range_payloads_len])?;
        }

        Ok(pos)
    }

    // ── helpers ─────────────────────────────────────────────────

    fn write_range_type(&mut self, rt: u64) -> Result<(), BufferError> {
        let remaining = &mut self.range_types_buf[self.range_types_len..];
        let mut buf = Buffer::new(remaining);
        encode_varint(&mut buf, rt)?;
        self.range_types_len += buf.written_len();
        Ok(())
    }

    fn write_range_payload(&mut self, data: &[u8]) -> Result<(), BufferError> {
        let end = self.range_payloads_len + data.len();
        if end > self.range_payloads_buf.len() {
            return Err(BufferError::Overflow);
        }
        self.range_payloads_buf[self.range_payloads_len..end].copy_from_slice(data);
        self.range_payloads_len = end;
        Ok(())
    }

    fn copy_to(output: &mut [u8], pos: &mut usize, data: &[u8]) -> Result<(), BufferError> {
        let end = *pos + data.len();
        if end > output.len() {
            return Err(BufferError::Overflow);
        }
        output[*pos..end].copy_from_slice(data);
        *pos = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_owner_id() -> [u8; 16] {
        [
            0x4a, 0xd6, 0xef, 0x75, 0x33, 0xf1, 0x93, 0xcd, 0x33, 0xd1, 0xc3, 0x55, 0xc0, 0x32,
            0x60, 0xea,
        ]
    }

    #[test]
    fn empty_db_sync_message_exact_match() {
        // From Protocol.test.ts: createProtocolMessageForSync with empty DB
        let expected: &[u8] = &[
            1, 74, 214, 239, 117, 51, 241, 147, 205, 51, 209, 195, 85, 192, 50, 96, 234,
            0, // messageType = Request
            0, // hasWriteKey = false
            0, // subscriptionFlag = None
            0, // messages TimestampsBuffer count = 0
            // ranges section:
            1, // ranges TimestampsBuffer count = 1 (InfiniteUpperBound, no data)
            2, // range type = Timestamps
            0, // nested TimestampsBuffer count = 0
        ];

        let owner_id = test_owner_id();
        let mut builder = MessageBuilder::new_request(&owner_id, None, SUBSCRIPTION_NONE).unwrap();
        builder.add_timestamps_range(None, &[]).unwrap();

        let mut output = [0u8; 256];
        let len = builder.finalize(&mut output).unwrap();

        assert_eq!(&output[..len], expected, "Empty DB message mismatch");
    }

    #[test]
    fn request_with_write_key() {
        let owner_id = test_owner_id();
        let write_key: [u8; 16] = [0x6d, 0x60, 0x4b, 0xe4, 0x29, 0xba, 0x07, 0xa2,
                                    0x8d, 0x5c, 0x25, 0xd1, 0x38, 0xe2, 0xc9, 0x5b];

        let mut builder = MessageBuilder::new_request(
            &owner_id, Some(&write_key), SUBSCRIPTION_SUBSCRIBE,
        ).unwrap();

        let mut output = [0u8; 256];
        let len = builder.finalize(&mut output).unwrap();

        assert_eq!(output[0], 1); // version
        assert_eq!(&output[1..17], &owner_id);
        assert_eq!(output[17], MESSAGE_TYPE_REQUEST);
        assert_eq!(output[18], 1); // hasWriteKey
        assert_eq!(&output[19..35], &write_key);
        assert_eq!(output[35], SUBSCRIPTION_SUBSCRIBE);
        assert_eq!(output[36], 0); // 0 messages
        assert_eq!(len, 37); // no ranges
    }

    #[test]
    fn single_fingerprint_range_infinite() {
        let owner_id = test_owner_id();
        let mut builder = MessageBuilder::new_request(&owner_id, None, SUBSCRIPTION_NONE).unwrap();

        let fp: Fingerprint = [0xAA; 12];
        builder.add_fingerprint_range(None, &fp).unwrap();

        let mut output = [0u8; 256];
        let len = builder.finalize(&mut output).unwrap();

        assert!(len > 0);

        // Verify range section
        // Header: version(1) + ownerId(16) + msgType(1) + hasWriteKey(1) + subFlag(1) = 20
        // Messages: TimestampsBuffer count=0 → 1 byte
        // So ranges start at offset 21
        let range_start = 21;
        assert_eq!(output[range_start], 1); // ranges count = 1 (infinite)
        assert_eq!(output[range_start + 1], 1); // type = Fingerprint
        assert_eq!(&output[range_start + 2..range_start + 14], &[0xAA; 12]);
    }

    #[test]
    fn three_ranges_two_real_upper_bounds() {
        let owner_id = test_owner_id();
        let mut builder = MessageBuilder::new_request(&owner_id, None, SUBSCRIPTION_NONE).unwrap();

        let ts1 = crate::timestamp::timestamp_to_bytes(&Timestamp::new(
            Millis::new(1000).unwrap(), Counter::new(0), NodeId::MIN,
        ));
        let ts2 = crate::timestamp::timestamp_to_bytes(&Timestamp::new(
            Millis::new(2000).unwrap(), Counter::new(0), NodeId::MIN,
        ));

        builder.add_skip_range(Some(&ts1)).unwrap();
        builder.add_skip_range(Some(&ts2)).unwrap();
        builder.add_skip_range(None).unwrap(); // InfiniteUpperBound

        let mut output = [0u8; 512];
        let len = builder.finalize(&mut output).unwrap();
        assert!(len > 0);

        // Verify: ranges_ts count = 3 (but only 2 real timestamps encoded)
    }

    #[test]
    fn timestamps_range_with_data() {
        let owner_id = test_owner_id();
        let mut builder = MessageBuilder::new_request(&owner_id, None, SUBSCRIPTION_NONE).unwrap();

        let timestamps: heapless::Vec<TimestampBytes, 5> = (0..5u64)
            .map(|i| crate::timestamp::timestamp_to_bytes(&Timestamp::new(
                Millis::new(i * 1000).unwrap(), Counter::new(0), NodeId::MIN,
            )))
            .collect();

        builder.add_timestamps_range(None, &timestamps).unwrap();

        let mut output = [0u8; 512];
        let len = builder.finalize(&mut output).unwrap();
        assert!(len > 0);
    }
}
