//! Relay client — callback-driven Evolu RBSR sync protocol.
//!
//! Uses `MessageBuilder` for wire-compatible message construction and
//! `MessageHandler` for event-driven response processing.

#[cfg(feature = "std")]
extern crate alloc;
#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::message::MessageBuilder;
use crate::protocol::*;
use crate::storage::StorageBackend;
use crate::sync::*;
use crate::transport::{ConnectionState, HandleError, MessageHandler};
use crate::types::*;

/// Maximum protocol message buffer size (64 KB).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Relay sync state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    WaitingForResponse,
    Synced,
    Error,
}

/// A received CRDT message (timestamp + encrypted change bytes).
pub struct ReceivedMessage<'a> {
    pub timestamp: TimestampBytes,
    pub encrypted_change: &'a [u8],
}

/// Relay client with event-driven sync.
///
/// Implements `MessageHandler` — wire it to your transport's receive callback.
pub struct RelayClient<'a> {
    owner_id: &'a [u8; 16],
    encryption_key: &'a [u8; 32],
    write_key: Option<&'a [u8; 16]>,

    state: SyncState,
    rounds: u32,
    messages_received: u32,

    /// Outgoing message buffer. After `start_sync()` or after processing
    /// a response that needs a follow-up, this contains the message to send.
    out_buf: [u8; MAX_MESSAGE_SIZE],
    out_len: usize,

    /// Parsed response ranges (for multi-round RBSR).
    response_ranges: heapless::Vec<ParsedRange, 32>,

    /// Timestamps of CRDT messages received in the last response.
    received_timestamps: heapless::Vec<TimestampBytes, 256>,

    /// Raw encrypted change payloads corresponding to received_timestamps.
    /// Index i corresponds to received_timestamps[i].
    #[cfg(feature = "std")]
    received_changes: Vec<Vec<u8>>,
}

/// A parsed range from a relay response.
#[derive(Clone, Debug)]
pub enum ParsedRange {
    Skip { upper_bound: RangeUpperBound },
    Fingerprint { upper_bound: RangeUpperBound, fingerprint: Fingerprint },
    Timestamps { upper_bound: RangeUpperBound, timestamps: heapless::Vec<TimestampBytes, 256> },
}

impl<'a> RelayClient<'a> {
    pub fn new(
        owner_id: &'a [u8; 16],
        encryption_key: &'a [u8; 32],
        write_key: Option<&'a [u8; 16]>,
    ) -> Self {
        RelayClient {
            owner_id,
            encryption_key,
            write_key,
            state: SyncState::Idle,
            rounds: 0,
            messages_received: 0,
            out_buf: [0u8; MAX_MESSAGE_SIZE],
            out_len: 0,
            response_ranges: heapless::Vec::new(),
            received_timestamps: heapless::Vec::new(),
            #[cfg(feature = "std")]
            received_changes: Vec::new(),
        }
    }

    pub fn state(&self) -> SyncState { self.state }
    pub fn is_synced(&self) -> bool { self.state == SyncState::Synced }
    pub fn messages_received(&self) -> u32 { self.messages_received }
    pub fn rounds(&self) -> u32 { self.rounds }
    pub fn encryption_key(&self) -> &[u8; 32] { self.encryption_key }

    /// Get the pending outgoing message, if any. Consumed on first call.
    pub fn pending_send(&mut self) -> Option<&[u8]> {
        if self.out_len > 0 {
            let msg = &self.out_buf[..self.out_len];
            self.out_len = 0;
            Some(msg)
        } else {
            None
        }
    }

    /// Last response's parsed ranges (for inspection/testing).
    pub fn response_ranges(&self) -> &[ParsedRange] {
        &self.response_ranges
    }

    /// Timestamps of messages received in the last response.
    pub fn received_timestamps(&self) -> &[TimestampBytes] {
        &self.received_timestamps
    }

    /// Encrypted change payloads for received messages (std only).
    /// Index i corresponds to `received_timestamps()[i]`.
    #[cfg(feature = "std")]
    pub fn received_changes(&self) -> &[Vec<u8>] {
        &self.received_changes
    }

    /// Build and queue the initial sync request from storage state.
    ///
    /// After calling, use `pending_send()` to get the bytes to send.
    pub fn start_sync<S: StorageBackend>(
        &mut self,
        storage: &mut S,
    ) -> Result<(), BufferError> {
        let count = storage.size().map_err(|_| BufferError::Overflow)?;

        let mut builder = MessageBuilder::new_request(
            self.owner_id,
            self.write_key,
            SUBSCRIPTION_SUBSCRIBE,
        )?;

        Self::build_ranges_from_storage(&mut builder, storage, 0, count, None)?;

        self.out_len = builder.finalize(&mut self.out_buf)?;
        self.state = SyncState::WaitingForResponse;
        self.rounds = 0;
        self.messages_received = 0;
        self.response_ranges.clear();
        Ok(())
    }

    /// Build a follow-up sync request processing the response ranges.
    ///
    /// Call this after `on_message` if `!is_synced()`.
    pub fn continue_sync<S: StorageBackend>(
        &mut self,
        storage: &mut S,
    ) -> Result<(), BufferError> {
        let storage_size = storage.size().map_err(|_| BufferError::Overflow)?;

        let mut builder = MessageBuilder::new_request(
            self.owner_id,
            self.write_key,
            SUBSCRIPTION_NONE,
        )?;

        let ranges = core::mem::take(&mut self.response_ranges);
        let mut prev_index = 0u32;
        let mut any_non_skip = false;

        for range in &ranges {
            let upper_bound_ts = match range {
                ParsedRange::Skip { upper_bound }
                | ParsedRange::Fingerprint { upper_bound, .. }
                | ParsedRange::Timestamps { upper_bound, .. } => match upper_bound {
                    RangeUpperBound::Timestamp(ts) => Some(*ts),
                    RangeUpperBound::Infinite => None,
                },
            };

            // find_lower_bound: scan to find first timestamp >= bound
            let upper = if let Some(bound) = &upper_bound_ts {
                let mut found = storage_size;
                let _ = storage.iterate(prev_index, storage_size, &mut |ts, idx| {
                    if ts >= bound {
                        found = idx;
                        return false;
                    }
                    true
                });
                found
            } else {
                storage_size
            };

            match range {
                ParsedRange::Skip { upper_bound } => {
                    if any_non_skip {
                        match upper_bound {
                            RangeUpperBound::Infinite => builder.add_skip_range(None)?,
                            RangeUpperBound::Timestamp(ts) => builder.add_skip_range(Some(ts))?,
                        }
                    }
                }
                ParsedRange::Fingerprint { upper_bound, fingerprint: their_fp } => {
                    let our_fp = storage.fingerprint(prev_index, upper)
                        .unwrap_or(ZERO_FINGERPRINT);

                    if our_fp == *their_fp {
                        if any_non_skip {
                            match upper_bound {
                                RangeUpperBound::Infinite => builder.add_skip_range(None)?,
                                RangeUpperBound::Timestamp(ts) => builder.add_skip_range(Some(ts))?,
                            }
                        }
                    } else {
                        any_non_skip = true;
                        let _item_count = upper - prev_index;
                        let ub_ref = upper_bound_ts.as_ref();
                        Self::build_ranges_from_storage(
                            &mut builder, storage, prev_index, upper, ub_ref,
                        )?;
                    }
                }
                ParsedRange::Timestamps { upper_bound: ref ts_upper_bound, timestamps: their_ts } => {
                    // Pass 1: collect our timestamps
                    let mut our_ts: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();
                    let _ = storage.iterate(prev_index, upper, &mut |ts, _| {
                        let _ = our_ts.push(*ts);
                        true
                    });

                    // Pass 2: find which timestamps they don't have
                    let mut to_send: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();
                    for ts in &our_ts {
                        if !their_ts.contains(ts) {
                            let _ = to_send.push(*ts);
                        }
                    }

                    // Check if they have timestamps we still need
                    let mut we_need_theirs = false;
                    for ts in their_ts {
                        if !our_ts.contains(ts) {
                            we_need_theirs = true;
                            break;
                        }
                    }

                    if to_send.is_empty() && !we_need_theirs {
                        // Both sides have the same timestamps — skip
                        if any_non_skip {
                            match ts_upper_bound {
                                RangeUpperBound::Infinite => builder.add_skip_range(None)?,
                                RangeUpperBound::Timestamp(ts) => builder.add_skip_range(Some(ts))?,
                            }
                        }
                    } else {
                        // Pass 3: read and send changes (separate borrows)
                        for ts in &to_send {
                            if let Ok(Some(data)) = storage.read(ts) {
                                let _ = builder.add_message(ts, data);
                            }
                        }

                        any_non_skip = true;
                        let ub_ref = upper_bound_ts.as_ref();
                        builder.add_timestamps_range(ub_ref, &our_ts)?;
                    }
                }
            }

            prev_index = upper;
        }

        self.out_len = builder.finalize(&mut self.out_buf)?;
        self.state = SyncState::WaitingForResponse;
        Ok(())
    }

    /// Process an incoming relay message.
    fn handle_relay_message(&mut self, message: &[u8]) -> Result<(), HandleError> {
        self.rounds += 1;
        self.response_ranges.clear();
        self.received_timestamps.clear();
        #[cfg(feature = "std")]
        self.received_changes.clear();

        let mut parse_buf = [0u8; MAX_MESSAGE_SIZE];
        if message.len() > parse_buf.len() {
            self.state = SyncState::Error;
            return Err(HandleError::TooLarge);
        }
        parse_buf[..message.len()].copy_from_slice(message);
        let mut buf = Buffer::from_data(&mut parse_buf, message.len());

        // Header
        let version = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)?;
        if version != PROTOCOL_VERSION {
            // Version mismatch: relay responds with just version + ownerId (no messageType).
            // Consume the ownerId if present, then signal version mismatch.
            let _ = buf.shift_n(16);
            self.state = SyncState::Error;
            return Err(HandleError::VersionMismatch);
        }

        let _owner_id = buf.shift_n(16).map_err(|_| HandleError::ParseError)?;
        let message_type = buf.shift().map_err(|_| HandleError::ParseError)?;

        match message_type {
            MESSAGE_TYPE_RESPONSE => {
                let error_code = buf.shift().map_err(|_| HandleError::ParseError)?;
                if error_code != ERROR_NONE {
                    self.state = SyncState::Error;
                    return Err(match error_code {
                        ERROR_WRITE_KEY => HandleError::WriteKeyError,
                        ERROR_WRITE => HandleError::WriteError,
                        ERROR_QUOTA => HandleError::QuotaError,
                        ERROR_SYNC => HandleError::SyncError,
                        _ => HandleError::ParseError,
                    });
                }
            }
            MESSAGE_TYPE_BROADCAST => {}
            _ => {
                self.state = SyncState::Error;
                return Err(HandleError::ParseError);
            }
        }

        // Messages: timestamps + encrypted changes
        let mut msg_timestamps: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();
        decode_timestamps_buffer(&mut buf, |ts| { let _ = msg_timestamps.push(ts); })
            .map_err(|_| HandleError::ParseError)?;

        // Read encrypted change payloads
        for _ in 0..msg_timestamps.len() {
            let change_len = decode_length(&mut buf).map_err(|_| HandleError::ParseError)?;
            let change_bytes = buf.shift_n(change_len).map_err(|_| HandleError::ParseError)?;
            #[cfg(feature = "std")]
            self.received_changes.push(change_bytes.to_vec());
            #[cfg(not(feature = "std"))]
            let _ = change_bytes;
        }

        self.messages_received += msg_timestamps.len() as u32;
        for ts in &msg_timestamps {
            let _ = self.received_timestamps.push(*ts);
        }

        // Ranges
        if message_type == MESSAGE_TYPE_RESPONSE && buf.remaining() > 0 {
            // The ranges section starts with a TimestampsBuffer for upper bounds.
            // The TimestampsBuffer count = total number of ranges.
            // Only (count - 1) real timestamps are encoded (last is InfiniteUpperBound).
            let range_count = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)? as usize;

            if range_count > 0 {
                let mut upper_bounds: heapless::Vec<TimestampBytes, 32> = heapless::Vec::new();
                // Real timestamps = range_count - 1 (last range always has InfiniteUpperBound)
                let real_ub_count = range_count - 1;

                if real_ub_count > 0 {
                    // Decode delta millis
                    let mut millis_vals: heapless::Vec<u64, 32> = heapless::Vec::new();
                    let mut prev_m = 0u64;
                    for _ in 0..real_ub_count {
                        let delta = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)?;
                        prev_m += delta;
                        let _ = millis_vals.push(prev_m);
                    }

                    // Decode RLE counters
                    let mut counters: heapless::Vec<u16, 32> = heapless::Vec::new();
                    while counters.len() < real_ub_count {
                        let v = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)? as u16;
                        let run = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)? as usize;
                        for _ in 0..run { let _ = counters.push(v); }
                    }

                    // Decode RLE nodeIds
                    let mut nodes: heapless::Vec<NodeId, 32> = heapless::Vec::new();
                    while nodes.len() < real_ub_count {
                        let n = decode_node_id(&mut buf).map_err(|_| HandleError::ParseError)?;
                        let run = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)? as usize;
                        for _ in 0..run { let _ = nodes.push(n); }
                    }

                    // Assemble
                    for i in 0..real_ub_count {
                        let ts = Timestamp::new(
                            Millis::new(millis_vals[i]).map_err(|_| HandleError::ParseError)?,
                            Counter::new(counters[i]),
                            nodes[i],
                        );
                        let _ = upper_bounds.push(crate::timestamp::timestamp_to_bytes(&ts));
                    }
                }

                // Decode range types
                let mut range_types: heapless::Vec<u64, 32> = heapless::Vec::new();
                for _ in 0..range_count {
                    let rt = decode_varint(&mut buf).map_err(|_| HandleError::ParseError)?;
                    let _ = range_types.push(rt);
                }

                // Decode payloads and build ParsedRange list
                for i in 0..range_count {
                    let upper_bound = if i < upper_bounds.len() {
                        RangeUpperBound::Timestamp(upper_bounds[i])
                    } else {
                        RangeUpperBound::Infinite
                    };

                    match range_types[i] {
                        RANGE_TYPE_SKIP => {
                            let _ = self.response_ranges.push(ParsedRange::Skip { upper_bound });
                        }
                        RANGE_TYPE_FINGERPRINT => {
                            let fp_bytes = buf.shift_n(FINGERPRINT_SIZE).map_err(|_| HandleError::ParseError)?;
                            let mut fingerprint = [0u8; 12];
                            fingerprint.copy_from_slice(fp_bytes);
                            let _ = self.response_ranges.push(ParsedRange::Fingerprint { upper_bound, fingerprint });
                        }
                        RANGE_TYPE_TIMESTAMPS => {
                            let mut timestamps: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();
                            decode_timestamps_buffer(&mut buf, |ts| { let _ = timestamps.push(ts); })
                                .map_err(|_| HandleError::ParseError)?;
                            let _ = self.response_ranges.push(ParsedRange::Timestamps { upper_bound, timestamps });
                        }
                        _ => {
                            self.state = SyncState::Error;
                            return Err(HandleError::ParseError);
                        }
                    }
                }
            }
        }

        // Check if sync is complete
        let is_complete = self.response_ranges.is_empty()
            || self.response_ranges.iter().all(|r| matches!(r, ParsedRange::Skip { .. }));

        if is_complete {
            self.state = SyncState::Synced;
        }
        // If not complete, caller should call continue_sync() with storage state

        Ok(())
    }

    // ── Internal: range building from StorageBackend ────────────

    fn build_ranges_from_storage<S: StorageBackend>(
        builder: &mut MessageBuilder,
        storage: &mut S,
        lower: u32,
        upper: u32,
        upper_bound_ts: Option<&TimestampBytes>,
    ) -> Result<(), BufferError> {
        let item_count = upper - lower;
        if item_count == 0 {
            builder.add_timestamps_range(upper_bound_ts, &[])?;
            return Ok(());
        }

        let buckets = compute_balanced_buckets(item_count, DEFAULT_NUM_BUCKETS, DEFAULT_MIN_PER_BUCKET);

        match buckets {
            Err(_) => {
                // Too few items — send all as TimestampsRange
                let mut timestamps: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();
                let _ = storage.iterate(lower, upper, &mut |ts, _| {
                    let _ = timestamps.push(*ts);
                    true
                });
                builder.add_timestamps_range(upper_bound_ts, &timestamps)?;
            }
            Ok(bucket_boundaries) => {
                // Offset bucket boundaries by lower to get absolute positions.
                // When lower > 0, TS does fingerprintRanges(buckets).slice(1),
                // which skips the [0, lower) range. We achieve the same by
                // just offsetting without prepending lower.
                let adjusted: heapless::Vec<u32, 16> = if lower == 0 {
                    bucket_boundaries.clone()
                } else {
                    bucket_boundaries.iter().map(|&b| b + lower).collect()
                };

                let mut prev = lower;
                for (i, &boundary) in adjusted.iter().enumerate() {
                    let fp = storage.fingerprint(prev, boundary).unwrap_or(ZERO_FINGERPRINT);
                    let is_last = i == adjusted.len() - 1;

                    if is_last {
                        builder.add_fingerprint_range(upper_bound_ts, &fp)?;
                    } else {
                        let mut bound_ts = [0u8; 16];
                        let _ = storage.iterate(boundary - 1, boundary, &mut |ts, _| {
                            bound_ts = *ts;
                            false
                        });
                        builder.add_fingerprint_range(Some(&bound_ts), &fp)?;
                    }

                    prev = boundary;
                }
            }
        }

        Ok(())
    }
}

impl<'a> MessageHandler for RelayClient<'a> {
    fn on_message(&mut self, message: &[u8]) -> Result<(), HandleError> {
        self.handle_relay_message(message)
    }

    fn on_state_change(&mut self, new_state: ConnectionState) {
        if new_state == ConnectionState::Disconnected && self.state == SyncState::WaitingForResponse {
            self.state = SyncState::Error;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::timestamp_to_bytes;
    use crate::transport::{Transport, MessageHandler};
    use crate::transport::mock::*;

    extern crate alloc;

    fn test_owner_id() -> [u8; 16] {
        [0x4a, 0xd6, 0xef, 0x75, 0x33, 0xf1, 0x93, 0xcd,
         0x33, 0xd1, 0xc3, 0x55, 0xc0, 0x32, 0x60, 0xea]
    }

    fn test_enc_key() -> [u8; 32] {
        [0x5b, 0xf1, 0x4c, 0x7d, 0x9e, 0x75, 0xe3, 0x7d,
         0xe6, 0x32, 0x57, 0xcc, 0xa7, 0x50, 0x38, 0xe9,
         0xec, 0x20, 0x77, 0x72, 0x03, 0x85, 0x0b, 0x72,
         0xf5, 0x4c, 0xe6, 0x08, 0x7b, 0xbb, 0x9e, 0x73]
    }

    /// Minimal in-memory StorageBackend for tests.
    struct TestStorage {
        entries: alloc::vec::Vec<(TimestampBytes, alloc::vec::Vec<u8>)>,
    }

    impl TestStorage {
        fn new() -> Self { TestStorage { entries: alloc::vec::Vec::new() } }
        fn with_timestamps(count: u32) -> Self {
            let mut s = Self::new();
            for i in 0..count {
                let ts = timestamp_to_bytes(&Timestamp::new(
                    Millis::new(i as u64 * 1000).unwrap(), Counter::new(0), NodeId::MIN,
                ));
                s.insert(&ts, &[i as u8]).unwrap();
            }
            s
        }
    }

    impl StorageBackend for TestStorage {
        type Error = ();
        fn size(&mut self) -> Result<u32, ()> { Ok(self.entries.len() as u32) }
        fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, ()> {
            let mut fp = ZERO_FINGERPRINT;
            for i in begin..end.min(self.entries.len() as u32) {
                fp = fingerprint_xor(&fp, &crate::crypto::timestamp_to_fingerprint(&self.entries[i as usize].0));
            }
            Ok(fp)
        }
        fn iterate(&mut self, begin: u32, end: u32, cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool) -> Result<(), ()> {
            for i in begin..end.min(self.entries.len() as u32) {
                if !cb(&self.entries[i as usize].0, i) { break; }
            }
            Ok(())
        }
        fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), ()> {
            if !self.entries.iter().any(|e| e.0 == *ts) {
                let pos = self.entries.iter().position(|e| e.0 > *ts).unwrap_or(self.entries.len());
                self.entries.insert(pos, (*ts, data.to_vec()));
            }
            Ok(())
        }
        fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, ()> {
            Ok(self.entries.iter().find(|e| e.0 == *ts).map(|e| e.1.as_slice()))
        }
    }

    fn build_empty_response(owner_id: &[u8; 16]) -> alloc::vec::Vec<u8> {
        let mut b = [0u8; 64];
        let mut buf = Buffer::new(&mut b);
        encode_varint(&mut buf, PROTOCOL_VERSION).unwrap();
        buf.extend(owner_id).unwrap();
        buf.push(MESSAGE_TYPE_RESPONSE).unwrap();
        buf.push(ERROR_NONE).unwrap();
        encode_timestamps_buffer(&mut buf, &[]).unwrap();
        encode_varint(&mut buf, 0).unwrap();
        buf.written().to_vec()
    }

    #[test]
    fn start_sync_empty() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        assert_eq!(client.state(), SyncState::WaitingForResponse);
        let msg = client.pending_send().unwrap();
        assert_eq!(msg[0], 1);
    }

    #[test]
    fn start_sync_small() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::with_timestamps(5);
        client.start_sync(&mut storage).unwrap();
        assert!(client.pending_send().is_some());
    }

    #[test]
    fn start_sync_large_uses_fingerprint_ranges() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::with_timestamps(100);
        client.start_sync(&mut storage).unwrap();
        assert!(client.pending_send().is_some());
    }

    #[test]
    fn receive_empty_response_synced() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        let resp = build_empty_response(&oid);
        client.on_message(&resp).unwrap();

        assert!(client.is_synced());
        assert_eq!(client.rounds(), 1);
    }

    #[test]
    fn receive_error_response() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        let mut b = [0u8; 64];
        let mut buf = Buffer::new(&mut b);
        encode_varint(&mut buf, PROTOCOL_VERSION).unwrap();
        buf.extend(&oid).unwrap();
        buf.push(MESSAGE_TYPE_RESPONSE).unwrap();
        buf.push(ERROR_WRITE_KEY).unwrap();

        assert!(client.on_message(buf.written()).is_err());
        assert_eq!(client.state(), SyncState::Error);
    }

    #[test]
    fn full_sync_via_mock_transport() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let (mut transport, _relay) = create_mock_pair();
        transport.connect(&[0u8; 16]).unwrap();

        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        transport.send(client.pending_send().unwrap()).unwrap();

        let resp = build_empty_response(&oid);
        transport.inject_message(&resp);
        transport.deliver_one(&mut client);

        assert!(client.is_synced());
    }

    #[test]
    fn disconnect_during_sync() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        client.on_state_change(ConnectionState::Disconnected);
        assert_eq!(client.state(), SyncState::Error);
    }

    #[test]
    fn pending_send_consumed_once() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        assert!(client.pending_send().is_some());
        assert!(client.pending_send().is_none());
    }

    #[test]
    fn receive_response_with_skip_ranges_is_synced() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);
        let mut storage = TestStorage::new();
        client.start_sync(&mut storage).unwrap();

        let mut b = [0u8; 128];
        let mut buf = Buffer::new(&mut b);
        encode_varint(&mut buf, PROTOCOL_VERSION).unwrap();
        buf.extend(&oid).unwrap();
        buf.push(MESSAGE_TYPE_RESPONSE).unwrap();
        buf.push(ERROR_NONE).unwrap();
        encode_timestamps_buffer(&mut buf, &[]).unwrap();
        encode_varint(&mut buf, 1).unwrap();
        encode_varint(&mut buf, RANGE_TYPE_SKIP).unwrap();

        client.on_message(buf.written()).unwrap();
        assert!(client.is_synced());
    }
}
