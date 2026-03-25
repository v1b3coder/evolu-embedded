# Review Findings

## Summary

This review compared the Rust port in `evolu-embedded` against the design goals in `RUST.md`, the upstream TypeScript protocol implementation in `../packages/common/src/local-first/Protocol.ts`, and the upstream TypeScript tests in `../packages/common/test/local-first/Protocol.test.ts`.

The Rust workspace test suite currently passes with `cargo test`, but the audit found several protocol and correctness issues that are not covered by the Rust tests.

## Findings

### 1. High: outgoing CRDT payloads are silently truncated to 4 KiB

In follow-up sync rounds, the Rust client copies each `EncryptedDbChange` into a fixed 4096-byte buffer and sends only the copied prefix:

- [`crates/evolu-core/src/relay.rs:243`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L243)
- [`crates/evolu-core/src/relay.rs:250`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L250)

This produces corrupted messages for any entry larger than 4096 bytes instead of failing cleanly or continuing sync in another round.

Upstream TypeScript does not truncate. It only adds a message when it fits within protocol limits, otherwise it closes the current range and continues in a later round:

- [`../packages/common/src/local-first/Protocol.ts:1367`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1367)
- [`../packages/common/src/local-first/Protocol.ts:1414`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1414)

Impact:

- Valid Evolu protocol messages can become undecryptable after Rust re-encodes them.
- This breaks wire compatibility and can cause sync divergence or data loss.

### 2. High: `Timestamps` reconciliation does not collapse to `Skip` when both sides already match

In the Rust follow-up sync path, a `Timestamps` range always results in `add_timestamps_range(...)`, even when the peer already has the same timestamps and there is nothing to send:

- [`crates/evolu-core/src/relay.rs:227`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L227)
- [`crates/evolu-core/src/relay.rs:255`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L255)

The upstream TypeScript implementation explicitly emits `skipRange(range)` when no timestamps are needed:

- [`../packages/common/src/local-first/Protocol.ts:1356`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1356)
- [`../packages/common/src/local-first/Protocol.ts:1414`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1414)

Impact:

- Two synchronized peers can keep exchanging equivalent `Timestamps` ranges instead of converging.
- This is a protocol convergence bug, not just an inefficiency.

### 3. High: oversized encrypted changes can panic during decryption

The Rust decrypt path trusts the encoded ciphertext length, then copies into a fixed 2048-byte plaintext buffer:

- [`crates/evolu-core/src/protocol.rs:558`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/protocol.rs#L558)
- [`crates/evolu-core/src/protocol.rs:560`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/protocol.rs#L560)

If `plaintext_len > 2048`, the slice operation panics before returning `ProtocolError`.

The encrypt path uses the same fixed-size 2048-byte temporary buffers:

- [`crates/evolu-core/src/protocol.rs:466`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/protocol.rs#L466)
- [`crates/evolu-core/src/protocol.rs:508`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/protocol.rs#L508)

Impact:

- A remotely supplied, length-valid message can crash the process instead of being rejected.
- This is a denial-of-service risk and contradicts the compatibility claims in `RUST.md`.

### 4. Medium: range splitting for `lower > 0` is not TS-equivalent

The Rust `build_ranges_from_storage` logic prepends `lower` to the adjusted bucket boundaries, but then still emits the first range instead of dropping the empty `[lower, lower)` segment:

- [`crates/evolu-core/src/relay.rs:456`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L456)
- [`crates/evolu-core/src/relay.rs:485`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L485)

The upstream TypeScript logic explicitly slices the first range off when `lower > 0`:

- [`../packages/common/src/local-first/Protocol.ts:1484`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1484)
- [`../packages/common/src/local-first/Protocol.ts:1502`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1502)

Impact:

- Follow-up rounds can contain an extra zero-fingerprint range that does not exist in the reference protocol flow.
- This risks needless extra rounds or mismatched reconciliation behavior.

### 5. Medium: version negotiation and protocol errors are not handled compatibly

Rust currently treats a version mismatch as a parse error:

- [`crates/evolu-core/src/relay.rs:283`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L283)
- [`crates/evolu-core/src/relay.rs:288`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L288)

It also collapses all non-zero response error codes into a generic parse error:

- [`crates/evolu-core/src/relay.rs:293`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L293)
- [`crates/evolu-core/src/relay.rs:299`](/home/dev/projekty/evolu/evolu-embedded/crates/evolu-core/src/relay.rs#L299)

Upstream TypeScript behaves differently:

- A relay responds to version mismatch with `version + ownerId` only:
  [`../packages/common/src/local-first/Protocol.ts:1066`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L1066)
- The client maps relay error codes to typed protocol errors:
  [`../packages/common/src/local-first/Protocol.ts:943`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L943)
  [`../packages/common/src/local-first/Protocol.ts:967`](/home/dev/projekty/evolu/packages/common/src/local-first/Protocol.ts#L967)

Impact:

- The Rust client cannot participate correctly in Evolu’s protocol version negotiation.
- Caller-visible error handling loses information needed to distinguish invalid write keys, quota failures, and sync failures.

## Test Coverage Notes

The upstream TypeScript suite does cover several of these protocol semantics:

- Timestamp tamper-proofing:
  [`../packages/common/test/local-first/Protocol.test.ts:480`](/home/dev/projekty/evolu/packages/common/test/local-first/Protocol.test.ts#L480)
- Version negotiation:
  [`../packages/common/test/local-first/Protocol.test.ts:671`](/home/dev/projekty/evolu/packages/common/test/local-first/Protocol.test.ts#L671)
- Protocol error mapping:
  [`../packages/common/test/local-first/Protocol.test.ts:743`](/home/dev/projekty/evolu/packages/common/test/local-first/Protocol.test.ts#L743)
- End-to-end multi-round sync convergence:
  [`../packages/common/test/local-first/Protocol.test.ts:923`](/home/dev/projekty/evolu/packages/common/test/local-first/Protocol.test.ts#L923)
- Forced continuation under size pressure:
  [`../packages/common/test/local-first/Protocol.test.ts:1260`](/home/dev/projekty/evolu/packages/common/test/local-first/Protocol.test.ts#L1260)

The Rust test suite does not currently contain focused coverage for:

- `Timestamps` range collapsing to `Skip` when both sides already match.
- Range splitting behavior when `lower > 0`.
- Oversized encrypted changes crossing the Rust fixed buffer ceilings.
- Version mismatch responses that use Evolu’s actual negotiation format.

## Verification

The Rust workspace test suite was executed:

```bash
cargo test
```

All current Rust tests passed during this review, which indicates these issues are largely test coverage gaps and protocol parity gaps rather than already-detected regressions.
