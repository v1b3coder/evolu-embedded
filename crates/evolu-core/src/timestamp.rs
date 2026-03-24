//! Hybrid Logical Clock (HLC) implementation.
//!
//! Port of `packages/common/src/local-first/Timestamp.ts`.

use crate::types::*;
use core::cmp::{max, Ordering};

/// Default maximum allowed clock drift (5 minutes in ms).
pub const DEFAULT_MAX_DRIFT: u64 = 5 * 60 * 1000;

/// Encode a Timestamp into a 16-byte sortable binary representation.
///
/// Layout: 6 bytes millis (BE) + 2 bytes counter (BE) + 8 bytes nodeId.
pub fn timestamp_to_bytes(ts: &Timestamp) -> TimestampBytes {
    let mut bytes = [0u8; 16];
    let m = ts.millis.value();

    // 6 bytes big-endian millis
    bytes[0] = ((m >> 40) & 0xFF) as u8;
    bytes[1] = ((m >> 32) & 0xFF) as u8;
    bytes[2] = ((m >> 24) & 0xFF) as u8;
    bytes[3] = ((m >> 16) & 0xFF) as u8;
    bytes[4] = ((m >> 8) & 0xFF) as u8;
    bytes[5] = (m & 0xFF) as u8;

    // 2 bytes big-endian counter
    let c = ts.counter.value();
    bytes[6] = ((c >> 8) & 0xFF) as u8;
    bytes[7] = (c & 0xFF) as u8;

    // 8 bytes nodeId
    bytes[8..16].copy_from_slice(&ts.node_id.0);

    bytes
}

/// Decode a 16-byte binary representation back to a Timestamp.
pub fn bytes_to_timestamp(bytes: &TimestampBytes) -> Timestamp {
    let millis = ((bytes[0] as u64) << 40)
        | ((bytes[1] as u64) << 32)
        | ((bytes[2] as u64) << 24)
        | ((bytes[3] as u64) << 16)
        | ((bytes[4] as u64) << 8)
        | (bytes[5] as u64);

    let counter = ((bytes[6] as u16) << 8) | (bytes[7] as u16);

    let mut node_id = [0u8; 8];
    node_id.copy_from_slice(&bytes[8..16]);

    Timestamp {
        millis: Millis::new(millis).unwrap_or(Millis::new(0).unwrap()),
        counter: Counter::new(counter),
        node_id: NodeId(node_id),
    }
}

/// Lexicographic comparison of TimestampBytes (equals temporal ordering).
pub fn order_timestamp_bytes(a: &TimestampBytes, b: &TimestampBytes) -> Ordering {
    a.cmp(b)
}

/// Compute the next millis value given the current time and previous millis values.
/// Returns error if drift exceeds max_drift or time is out of range.
fn get_next_millis(now: u64, millis: &[u64], max_drift: u64) -> Result<u64, TimestampError> {
    if now > MAX_MILLIS {
        return Err(TimestampError::TimeOutOfRange);
    }
    let mut next = now;
    for &m in millis {
        if m > next {
            next = m;
        }
    }
    if next - now > max_drift {
        Err(TimestampError::Drift { next, now })
    } else {
        Ok(next)
    }
}

/// Advance the clock when generating a local mutation.
///
/// Mirrors `sendTimestamp` in TypeScript.
pub fn send_timestamp(
    current: &Timestamp,
    now_millis: u64,
    max_drift: u64,
) -> Result<Timestamp, TimestampError> {
    let next = get_next_millis(now_millis, &[current.millis.value()], max_drift)?;

    let counter = if next == current.millis.value() {
        current.counter.increment()?
    } else {
        Counter::new(MIN_COUNTER)
    };

    Ok(Timestamp {
        millis: Millis::new(next)?,
        counter,
        node_id: current.node_id,
    })
}

/// Advance the clock when receiving a remote message.
///
/// Mirrors `receiveTimestamp` in TypeScript.
pub fn receive_timestamp(
    local: &Timestamp,
    remote: &Timestamp,
    now_millis: u64,
    max_drift: u64,
) -> Result<Timestamp, TimestampError> {
    let next = get_next_millis(
        now_millis,
        &[local.millis.value(), remote.millis.value()],
        max_drift,
    )?;

    let counter = if next == local.millis.value() && next == remote.millis.value() {
        // Both equal: increment max of both counters
        Counter::new(max(local.counter.value(), remote.counter.value())).increment()?
    } else if next == local.millis.value() {
        local.counter.increment()?
    } else if next == remote.millis.value() {
        remote.counter.increment()?
    } else {
        Counter::new(MIN_COUNTER)
    };

    Ok(Timestamp {
        millis: Millis::new(next)?,
        counter,
        node_id: local.node_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(millis: u64, counter: u16, node_id: &str) -> Timestamp {
        Timestamp {
            millis: Millis::new(millis).unwrap(),
            counter: Counter::new(counter),
            node_id: NodeId::from_hex(node_id).unwrap(),
        }
    }

    fn zero() -> Timestamp {
        Timestamp::zero()
    }

    // ── sendTimestamp tests ──────────────────────────────────────

    #[test]
    fn send_monotonic_clock() {
        // now=1, current=(0,0) → (1,0)
        let result = send_timestamp(&zero(), 1, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 1);
        assert_eq!(result.counter.value(), 0);
        assert_eq!(result.node_id, NodeId::MIN);
    }

    #[test]
    fn send_stuttering_clock() {
        // now=0, current=(0,0) → (0,1)
        let result = send_timestamp(&zero(), 0, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 0);
        assert_eq!(result.counter.value(), 1);
    }

    #[test]
    fn send_regressing_clock() {
        // now=0, current=(1,0) → (1,1)
        let current = ts(1, 0, "0000000000000000");
        let result = send_timestamp(&current, 0, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 1);
        assert_eq!(result.counter.value(), 1);
    }

    #[test]
    fn send_counter_overflow() {
        let mut result = Ok(zero());
        for _ in 0..65536 {
            match result {
                Ok(ref t) => result = send_timestamp(t, 0, DEFAULT_MAX_DRIFT),
                Err(_) => break,
            }
        }
        assert_eq!(result, Err(TimestampError::CounterOverflow));
    }

    #[test]
    fn send_clock_drift() {
        let current = ts(DEFAULT_MAX_DRIFT + 1, 0, "0000000000000000");
        let result = send_timestamp(&current, 0, DEFAULT_MAX_DRIFT);
        assert_eq!(
            result,
            Err(TimestampError::Drift {
                next: DEFAULT_MAX_DRIFT + 1,
                now: 0
            })
        );
    }

    // ── receiveTimestamp tests ───────────────────────────────────

    fn node1(millis: u64, counter: u16) -> Timestamp {
        ts(millis, counter, "0000000000000001")
    }

    fn node2(millis: u64, counter: u16) -> Timestamp {
        ts(millis, counter, "0000000000000002")
    }

    #[test]
    fn receive_wall_clock_later() {
        // now=1, both at millis=0 → (1, 0, node1)
        let result = receive_timestamp(&node1(0, 0), &node2(0, 0), 1, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 1);
        assert_eq!(result.counter.value(), 0);
        assert_eq!(result.node_id, NodeId::from_hex("0000000000000001").unwrap());
    }

    #[test]
    fn receive_same_millis_increment_max_counter() {
        // now=1, local=(1,0), remote=(1,1) → (1, 2, node1)
        let result = receive_timestamp(&node1(1, 0), &node2(1, 1), 1, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 1);
        assert_eq!(result.counter.value(), 2);

        // now=0, local=(1,1), remote=(1,0) → (1, 2, node1)
        let result = receive_timestamp(&node1(1, 1), &node2(1, 0), 0, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 1);
        assert_eq!(result.counter.value(), 2);
    }

    #[test]
    fn receive_local_millis_later() {
        // now=0, local=(2,0), remote=(1,0) → (2, 1, node1)
        let result = receive_timestamp(&node1(2, 0), &node2(1, 0), 0, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 2);
        assert_eq!(result.counter.value(), 1);
    }

    #[test]
    fn receive_remote_millis_later() {
        // now=0, local=(1,0), remote=(2,0) → (2, 1, node1)
        let result = receive_timestamp(&node1(1, 0), &node2(2, 0), 0, DEFAULT_MAX_DRIFT).unwrap();
        assert_eq!(result.millis.value(), 2);
        assert_eq!(result.counter.value(), 1);
    }

    #[test]
    fn receive_clock_drift() {
        let local = ts(DEFAULT_MAX_DRIFT + 1, 0, "0000000000000001");
        let result = receive_timestamp(&local, &node2(0, 0), 0, DEFAULT_MAX_DRIFT);
        assert_eq!(
            result,
            Err(TimestampError::Drift {
                next: DEFAULT_MAX_DRIFT + 1,
                now: 0
            })
        );

        let remote = ts(DEFAULT_MAX_DRIFT + 1, 0, "0000000000000002");
        let result = receive_timestamp(&node1(0, 0), &remote, 0, DEFAULT_MAX_DRIFT);
        assert_eq!(
            result,
            Err(TimestampError::Drift {
                next: DEFAULT_MAX_DRIFT + 1,
                now: 0
            })
        );
    }

    // ── Encoding tests ──────────────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let t = zero();
        let bytes = timestamp_to_bytes(&t);
        let decoded = bytes_to_timestamp(&bytes);
        assert_eq!(t, decoded);

        // Max millis
        let t = ts(MAX_MILLIS, 0, "0000000000000000");
        let bytes = timestamp_to_bytes(&t);
        let decoded = bytes_to_timestamp(&bytes);
        assert_eq!(decoded.millis.value(), MAX_MILLIS);
    }

    #[test]
    fn ordering_millis() {
        let t1 = timestamp_to_bytes(&ts(0, 0, "0000000000000000"));
        let t2 = timestamp_to_bytes(&ts(1, 0, "0000000000000000"));
        assert_eq!(order_timestamp_bytes(&t1, &t2), Ordering::Less);
        assert_eq!(order_timestamp_bytes(&t2, &t1), Ordering::Greater);
        assert_eq!(order_timestamp_bytes(&t1, &t1), Ordering::Equal);
    }

    #[test]
    fn ordering_counter() {
        let t1 = timestamp_to_bytes(&ts(0, 0, "0000000000000000"));
        let t2 = timestamp_to_bytes(&ts(0, 1, "0000000000000000"));
        assert_eq!(order_timestamp_bytes(&t1, &t2), Ordering::Less);
        assert_eq!(order_timestamp_bytes(&t2, &t1), Ordering::Greater);
    }

    #[test]
    fn ordering_node_id() {
        let t1 = timestamp_to_bytes(&ts(0, 0, "0000000000000000"));
        let t2 = timestamp_to_bytes(&ts(0, 0, "0000000000000001"));
        assert_eq!(order_timestamp_bytes(&t1, &t2), Ordering::Less);
        assert_eq!(order_timestamp_bytes(&t2, &t1), Ordering::Greater);
    }
}
