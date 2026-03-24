//! RBSR (Range-Based Set Reconciliation) sync engine.
//!
//! Port of the sync algorithm from `packages/common/src/local-first/Protocol.ts`
//! and `packages/common/src/Number.ts`.

use crate::types::*;

/// Default number of buckets for fingerprint range splitting.
pub const DEFAULT_NUM_BUCKETS: u32 = 16;

/// Default minimum items per bucket.
pub const DEFAULT_MIN_PER_BUCKET: u32 = 2;

/// Divide `num_items` into `num_buckets` balanced buckets.
///
/// Returns bucket boundaries as indices. Each bucket has approximately
/// `num_items / num_buckets` items, with remainder distributed to first buckets.
///
/// Port of `computeBalancedBuckets` from `Number.ts`.
///
/// Returns `Err(min_required)` if there aren't enough items.
pub fn compute_balanced_buckets(
    num_items: u32,
    num_buckets: u32,
    min_per_bucket: u32,
) -> Result<heapless::Vec<u32, 16>, u32> {
    let min_required = num_buckets * min_per_bucket;
    if num_items < min_required {
        return Err(min_required);
    }

    let items_per_bucket = num_items / num_buckets;
    let extra_items = num_items % num_buckets;

    let mut boundaries = heapless::Vec::new();
    let mut boundary: u32 = 0;

    for i in 0..num_buckets {
        let extra = if i < extra_items { 1 } else { 0 };
        boundary += items_per_bucket + extra;
        let _ = boundaries.push(boundary);
    }

    Ok(boundaries)
}

/// Range types used in RBSR protocol.
#[derive(Clone, Debug, PartialEq)]
pub enum Range {
    /// Both sides agree this range is identical — skip it.
    Skip {
        upper_bound: RangeUpperBound,
    },
    /// A fingerprint for comparison. If it matches the other side's
    /// fingerprint for the same range, the data is identical.
    Fingerprint {
        upper_bound: RangeUpperBound,
        fingerprint: Fingerprint,
    },
    /// Explicit list of timestamps in this range.
    /// Used when the range is small enough to enumerate.
    Timestamps {
        upper_bound: RangeUpperBound,
        timestamps: heapless::Vec<TimestampBytes, 64>,
    },
}

/// Upper bound for a range — either a specific timestamp or infinite.
#[derive(Clone, Debug, PartialEq)]
pub enum RangeUpperBound {
    Timestamp(TimestampBytes),
    Infinite,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_buckets_basic() {
        // 10 items, 3 buckets, min 2 → [4, 7, 10]
        let result = compute_balanced_buckets(10, 3, 2).unwrap();
        assert_eq!(result.as_slice(), &[4, 7, 10]);
    }

    #[test]
    fn balanced_buckets_too_few_items() {
        // 5 items, 3 buckets, min 2 → need 6
        let result = compute_balanced_buckets(5, 3, 2);
        assert_eq!(result, Err(6));
    }

    #[test]
    fn balanced_buckets_exact_fit() {
        // 32 items, 16 buckets, min 2 → each bucket gets 2
        let result = compute_balanced_buckets(32, 16, 2).unwrap();
        assert_eq!(result.len(), 16);
        assert_eq!(*result.last().unwrap(), 32);
        // All buckets have exactly 2 items
        let mut prev = 0;
        for &b in result.iter() {
            assert_eq!(b - prev, 2);
            prev = b;
        }
    }

    #[test]
    fn balanced_buckets_with_remainder() {
        // 35 items, 16 buckets, min 2
        // 35 / 16 = 2 remainder 3
        // First 3 buckets get 3 items, rest get 2
        let result = compute_balanced_buckets(35, 16, 2).unwrap();
        assert_eq!(result.len(), 16);
        assert_eq!(*result.last().unwrap(), 35);

        let mut prev = 0;
        for (i, &b) in result.iter().enumerate() {
            let size = b - prev;
            if i < 3 {
                assert_eq!(size, 3, "bucket {} should have 3 items", i);
            } else {
                assert_eq!(size, 2, "bucket {} should have 2 items", i);
            }
            prev = b;
        }
    }

    #[test]
    fn balanced_buckets_default_params() {
        // 100 items with defaults (16 buckets, min 2)
        let result = compute_balanced_buckets(100, DEFAULT_NUM_BUCKETS, DEFAULT_MIN_PER_BUCKET).unwrap();
        assert_eq!(result.len(), 16);
        assert_eq!(*result.last().unwrap(), 100);
    }

    #[test]
    fn balanced_buckets_min_required() {
        // Exactly minimum required
        let result = compute_balanced_buckets(32, 16, 2).unwrap();
        assert_eq!(*result.last().unwrap(), 32);

        // One less than minimum
        assert!(compute_balanced_buckets(31, 16, 2).is_err());
    }
}
