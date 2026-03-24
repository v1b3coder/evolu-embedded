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

    /// Build and queue the initial sync request.
    ///
    /// After calling, use `pending_send()` to get the bytes to send.
    pub fn start_sync(
        &mut self,
        timestamp_count: u32,
        fingerprint_fn: &mut dyn FnMut(u32, u32) -> Option<Fingerprint>,
        iterate_fn: &mut dyn FnMut(u32, u32, &mut dyn FnMut(&TimestampBytes, u32) -> bool),
    ) -> Result<(), BufferError> {
        let mut builder = MessageBuilder::new_request(
            self.owner_id,
            self.write_key,
            SUBSCRIPTION_SUBSCRIBE,
        )?;

        self.build_ranges(&mut builder, timestamp_count, fingerprint_fn, iterate_fn)?;

        self.out_len = builder.finalize(&mut self.out_buf)?;
        self.state = SyncState::WaitingForResponse;
        self.rounds = 0;
        self.messages_received = 0;
        self.response_ranges.clear();
        Ok(())
    }

    /// Build a follow-up sync request processing the response ranges.
    ///
    /// Call this after `on_message` if `!is_synced()` and you have local
    /// storage state to compare against the response ranges.
    pub fn continue_sync(
        &mut self,
        storage_size: u32,
        fingerprint_fn: &mut dyn FnMut(u32, u32) -> Option<Fingerprint>,
        iterate_fn: &mut dyn FnMut(u32, u32, &mut dyn FnMut(&TimestampBytes, u32) -> bool),
        find_lower_bound_fn: &mut dyn FnMut(u32, u32, Option<&TimestampBytes>) -> Option<u32>,
        read_db_change_fn: &mut dyn FnMut(&TimestampBytes) -> Option<&[u8]>,
    ) -> Result<(), BufferError> {
        let mut builder = MessageBuilder::new_request(
            self.owner_id,
            self.write_key,
            SUBSCRIPTION_NONE, // Already subscribed
        )?;

        let ranges = core::mem::take(&mut self.response_ranges);
        let mut prev_index = 0u32;
        let mut any_non_skip = false;

        for range in &ranges {
            let upper_bound_ts = match range {
                ParsedRange::Skip { upper_bound }
                | ParsedRange::Fingerprint { upper_bound, .. }
                | ParsedRange::Timestamps { upper_bound, .. } => {
                    match upper_bound {
                        RangeUpperBound::Timestamp(ts) => Some(ts),
                        RangeUpperBound::Infinite => None,
                    }
                }
            };

            let upper = find_lower_bound_fn(
                prev_index, storage_size, upper_bound_ts.map(|t| &*t),
            ).unwrap_or(storage_size);

            match range {
                ParsedRange::Skip { upper_bound } => {
                    // Both sides agree — skip
                    if any_non_skip {
                        match upper_bound {
                            RangeUpperBound::Infinite => {
                                builder.add_skip_range(None)?;
                            }
                            RangeUpperBound::Timestamp(ts) => {
                                builder.add_skip_range(Some(ts))?;
                            }
                        }
                    }
                }
                ParsedRange::Fingerprint { upper_bound, fingerprint: their_fp } => {
                    let our_fp = fingerprint_fn(prev_index, upper).unwrap_or(ZERO_FINGERPRINT);

                    if our_fp == *their_fp {
                        // Match — skip
                        if any_non_skip {
                            match upper_bound {
                                RangeUpperBound::Infinite => builder.add_skip_range(None)?,
                                RangeUpperBound::Timestamp(ts) => builder.add_skip_range(Some(ts))?,
                            }
                        }
                    } else {
                        any_non_skip = true;
                        // Mismatch — split further
                        let item_count = upper - prev_index;
                        let ub_ts = match upper_bound {
                            RangeUpperBound::Timestamp(ts) => Some(ts),
                            RangeUpperBound::Infinite => None,
                        };
                        self.split_range(
                            &mut builder, prev_index, upper, ub_ts,
                            item_count, fingerprint_fn, iterate_fn,
                        )?;
                    }
                }
                ParsedRange::Timestamps { upper_bound, timestamps: their_ts } => {
                    // Compare sets: find what we have that they don't, and vice versa
                    let mut our_ts: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();

                    // Build set of their timestamps for lookup
                    iterate_fn(prev_index, upper, &mut |ts, _idx| {
                        let _ = our_ts.push(*ts);
                        // If they don't have it, we need to send it
                        if !their_ts.contains(ts) {
                            if let Some(change) = read_db_change_fn(ts) {
                                let _ = builder.add_message(ts, change);
                            }
                        }
                        true
                    });

                    // They need our timestamps list to know what we have
                    any_non_skip = true;
                    let ub_ts = match upper_bound {
                        RangeUpperBound::Timestamp(ts) => Some(ts),
                        RangeUpperBound::Infinite => None,
                    };
                    builder.add_timestamps_range(ub_ts, &our_ts)?;
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
            self.state = SyncState::Error;
            return Err(HandleError::ParseError);
        }

        let _owner_id = buf.shift_n(16).map_err(|_| HandleError::ParseError)?;
        let message_type = buf.shift().map_err(|_| HandleError::ParseError)?;

        match message_type {
            MESSAGE_TYPE_RESPONSE => {
                let error_code = buf.shift().map_err(|_| HandleError::ParseError)?;
                if error_code != ERROR_NONE {
                    self.state = SyncState::Error;
                    return Err(HandleError::ParseError);
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

    // ── Internal: range building ────────────────────────────────

    fn build_ranges(
        &self,
        builder: &mut MessageBuilder,
        timestamp_count: u32,
        fingerprint_fn: &mut dyn FnMut(u32, u32) -> Option<Fingerprint>,
        iterate_fn: &mut dyn FnMut(u32, u32, &mut dyn FnMut(&TimestampBytes, u32) -> bool),
    ) -> Result<(), BufferError> {
        if timestamp_count == 0 {
            builder.add_timestamps_range(None, &[])?;
        } else {
            self.split_range(
                builder, 0, timestamp_count, None,
                timestamp_count, fingerprint_fn, iterate_fn,
            )?;
        }
        Ok(())
    }

    fn split_range(
        &self,
        builder: &mut MessageBuilder,
        lower: u32,
        upper: u32,
        upper_bound_ts: Option<&TimestampBytes>,
        item_count: u32,
        fingerprint_fn: &mut dyn FnMut(u32, u32) -> Option<Fingerprint>,
        iterate_fn: &mut dyn FnMut(u32, u32, &mut dyn FnMut(&TimestampBytes, u32) -> bool),
    ) -> Result<(), BufferError> {
        let buckets = compute_balanced_buckets(item_count, DEFAULT_NUM_BUCKETS, DEFAULT_MIN_PER_BUCKET);

        match buckets {
            Err(_) => {
                // Too few items — send all as TimestampsRange
                let mut timestamps: heapless::Vec<TimestampBytes, 256> = heapless::Vec::new();
                iterate_fn(lower, upper, &mut |ts, _| {
                    let _ = timestamps.push(*ts);
                    true
                });
                builder.add_timestamps_range(upper_bound_ts, &timestamps)?;
            }
            Ok(bucket_boundaries) => {
                // Split into FingerprintRanges
                let adjusted: heapless::Vec<u32, 16> = if lower == 0 {
                    bucket_boundaries.clone()
                } else {
                    let mut v = heapless::Vec::new();
                    let _ = v.push(lower);
                    for &b in bucket_boundaries.iter() {
                        let _ = v.push(b + lower);
                    }
                    v
                };

                let mut prev = if lower == 0 { 0 } else { lower };
                for (i, &boundary) in adjusted.iter().enumerate() {
                    let fp = fingerprint_fn(prev, boundary).unwrap_or(ZERO_FINGERPRINT);

                    // Upper bound: for last range use the caller's upper_bound_ts (or None=Infinite)
                    let is_last = i == adjusted.len() - 1;
                    if is_last {
                        builder.add_fingerprint_range(upper_bound_ts, &fp)?;
                    } else {
                        // Get the actual timestamp at boundary-1 as upper bound
                        let mut bound_ts = [0u8; 16];
                        iterate_fn(boundary - 1, boundary, &mut |ts, _| {
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
    use crate::crypto::timestamp_to_fingerprint;
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

        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

        assert_eq!(client.state(), SyncState::WaitingForResponse);
        let msg = client.pending_send().unwrap();
        assert_eq!(msg[0], 1); // protocol version
    }

    #[test]
    fn start_sync_small() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);

        let timestamps: alloc::vec::Vec<TimestampBytes> = (0..5)
            .map(|i| timestamp_to_bytes(&Timestamp::new(
                Millis::new(i * 1000).unwrap(), Counter::new(0), NodeId::MIN,
            ))).collect();

        let mut fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut it = |b: u32, e: u32, cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {
            for i in b..e { if !cb(&timestamps[i as usize], i) { break; } }
        };
        client.start_sync(5, &mut fp, &mut it).unwrap();
        assert!(client.pending_send().is_some());
    }

    #[test]
    fn start_sync_large_uses_fingerprint_ranges() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);

        let timestamps: alloc::vec::Vec<TimestampBytes> = (0..100)
            .map(|i| timestamp_to_bytes(&Timestamp::new(
                Millis::new(i * 1000).unwrap(), Counter::new(0), NodeId::MIN,
            ))).collect();

        let mut fp = |b: u32, e: u32| -> Option<Fingerprint> {
            let mut f = ZERO_FINGERPRINT;
            for i in b..e { f = fingerprint_xor(&f, &timestamp_to_fingerprint(&timestamps[i as usize])); }
            Some(f)
        };
        let mut it = |b: u32, e: u32, cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {
            for i in b..e { if !cb(&timestamps[i as usize], i) { break; } }
        };
        client.start_sync(100, &mut fp, &mut it).unwrap();
        assert!(client.pending_send().is_some());
    }

    #[test]
    fn receive_empty_response_synced() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);

        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

        let resp = build_empty_response(&oid);
        client.on_message(&resp).unwrap();

        assert!(client.is_synced());
        assert_eq!(client.rounds(), 1);
        assert_eq!(client.messages_received(), 0);
    }

    #[test]
    fn receive_error_response() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);

        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

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
        transport.connect().unwrap();

        let mut client = RelayClient::new(&oid, &ek, None);
        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

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

        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

        client.on_state_change(ConnectionState::Disconnected);
        assert_eq!(client.state(), SyncState::Error);
    }

    #[test]
    fn pending_send_consumed_once() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);

        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

        assert!(client.pending_send().is_some());
        assert!(client.pending_send().is_none());
    }

    #[test]
    fn receive_response_with_skip_ranges_is_synced() {
        let oid = test_owner_id();
        let ek = test_enc_key();
        let mut client = RelayClient::new(&oid, &ek, None);

        let mut no_fp = |_: u32, _: u32| -> Option<Fingerprint> { None };
        let mut no_iter = |_: u32, _: u32, _: &mut dyn FnMut(&TimestampBytes, u32) -> bool| {};
        client.start_sync(0, &mut no_fp, &mut no_iter).unwrap();

        // Build response with 1 SkipRange (InfiniteUpperBound)
        let mut b = [0u8; 128];
        let mut buf = Buffer::new(&mut b);
        encode_varint(&mut buf, PROTOCOL_VERSION).unwrap();
        buf.extend(&oid).unwrap();
        buf.push(MESSAGE_TYPE_RESPONSE).unwrap();
        buf.push(ERROR_NONE).unwrap();
        encode_timestamps_buffer(&mut buf, &[]).unwrap(); // 0 messages
        // Ranges: count=1 (TimestampsBuffer with 1 entry, infinite)
        encode_varint(&mut buf, 1).unwrap(); // count in TS buffer
        // No millis/counter/nodeId (infinite only increments count)
        // Range type = Skip
        encode_varint(&mut buf, RANGE_TYPE_SKIP).unwrap();

        client.on_message(buf.written()).unwrap();
        assert!(client.is_synced());
    }
}
