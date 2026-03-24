# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Pure Rust port of the Evolu local-first CRDT sync protocol, targeting STM32U5 (Cortex-M33) embedded hardware. `evolu-core` is `no_std` and compiles for `thumbv8m.main-none-eabihf`. The other crates are std-only (demo, testing, storage backends).

This is a port of the TypeScript Evolu project at `../packages/common/src/local-first/`. Protocol compatibility is verified against exact byte vectors from the TS test suite.

## Build and Test Commands

```bash
cargo test                    # all unit tests (124 tests)
cargo test -p evolu-core      # just core crate
cargo test -p evolu-stream-store # just host-storage backend
cargo test -- --ignored       # integration tests (needs relay running)

cargo build --release         # release build (all crates)

# Cross-compile core for STM32U5
cargo build -p evolu-core --target thumbv8m.main-none-eabihf --no-default-features

# Run the sync demo (needs relay — defaults to wss://free.evoluhq.com)
cargo run -p evolu-demo
cargo run -p evolu-demo -- ws://localhost:4000   # local relay

# Run a single test by name
cargo test -p evolu-core varint_test_vectors
```

## Architecture: Three Traits

Everything in `evolu-core` is generic over three traits. Each has separate implementations per platform.

**`StorageBackend`** (`storage.rs`) — where is my data?
- `evolu-stream-store`: streaming encrypted index on USB host + host data cache
- `evolu-file-store`: simple Vec-backed, std-only, for demo/testing

**`Transport` + `MessageHandler`** (`transport.rs`) — how do I talk to the relay?
- `evolu-ws-transport`: WebSocket via tungstenite (std, demo)
- Mock pair in `transport.rs` for unit testing
- USB CDC would be the embedded production implementation

**`Platform`** (`platform.rs`) — clock and randomness
- `evolu-std-platform` crate (SystemTime + getrandom)
- STM32U5 would use RTC + hardware TRNG

## Crate Dependency Graph

```
evolu-demo ──→ evolu-core (no_std)
           ──→ evolu-stream-store (std) ──→ evolu-core
           ──→ evolu-file-store (std) ──→ evolu-core
           ──→ evolu-std-platform (std) ──→ evolu-core
           ──→ evolu-ws-transport (std) ──→ evolu-core
```

`evolu-core` has zero std dependencies. All other crates are std-only.

## Key Design Constraints

- **evolu-core must stay `no_std`**: no `Vec`, `String`, `Box`, `HashMap`. Use `Buffer<'a>` (borrows caller's `&mut [u8]`) and `heapless::Vec<T, N>` (fixed capacity).
- **No `f64::fract()`** in no_std — use `(n as i64 as f64) != n` instead.
- **All data at rest is `EncryptedDbChange`**: the native Evolu protocol format. Both storage backends store the same encrypted blobs. The host never sees plaintext.
- **Protocol messages must be bit-exact** with TypeScript Evolu. Test vectors from TS are hardcoded in Rust tests. If you change encoding, verify against TS snapshots.

## evolu-core Module Map

- `types.rs` — `Millis`, `Counter`, `NodeId`, `Timestamp`, `TimestampBytes`, `Fingerprint`, `IdBytes`, `Buffer`
- `timestamp.rs` — HLC: `send_timestamp`, `receive_timestamp`, encode/decode
- `crypto.rs` — SLIP-21 key derivation, PADME padding, SHA-256 fingerprints
- `owner.rs` — `derive_owner(secret) → (id, encryption_key, write_key)` via SLIP-21
- `protocol.rs` — binary codec: varint, strings, flags, msgpack numbers, SqliteValue, EncryptedDbChange encrypt/decrypt
- `message.rs` — wire-compatible protocol message builder (header + messages + ranges sections)
- `crdt.rs` — LWW per-column merge logic
- `sync.rs` — `compute_balanced_buckets` for RBSR range splitting
- `relay.rs` — `RelayClient` implements `MessageHandler`, drives callback-based sync
- `storage.rs` — `StorageBackend` trait definition
- `transport.rs` — `Transport` + `MessageHandler` traits, `MockTransport` pair
- `platform.rs` — `Platform` trait (clock + randomness)

## evolu-stream-store (host-storage backend)

- `host.rs` — `HostInterface` trait: index streaming + data cache (no clock/random — those are in `Platform`)
- `file_host.rs` — `FileHost`: filesystem-backed `HostInterface` (index as `index.bin`, cache as `cache/*.bin`)
- `index.rs` — streaming encrypted index: chunk-based AEAD, 28-byte entries, replay detection
- `trusted_state.rs` — 64-byte on-chip state (`device_key`, `dir_sequence`, `clock`)
- `storage.rs` — `HostStorage<H, P>: StorageBackend` wiring index + cache + trusted state
## evolu-std-platform

Standalone `StdPlatform: Platform` using `SystemTime` + `getrandom`. Independent crate — any other crate can depend on it.

## Protocol Wire Format

Messages concatenate: `header || msg_timestamps || msg_dbchanges || range_timestamps || range_types || range_payloads`

The range upper bounds use a `TimestampsBuffer` where count = N ranges but only N-1 real timestamps (last is `InfiniteUpperBound` — only increments count, no data encoded). This is a critical detail for compatibility.

## Test Vectors from TypeScript

Protocol compatibility tests use exact byte arrays from `packages/common/test/local-first/Protocol.test.ts`. Key snapshots:
- Empty DB sync message: 24 bytes
- Varint: 14 value→bytes pairs
- MessagePack numbers: 57-byte concatenated snapshot
- SLIP-21: "all all all..." mnemonic → known hex outputs (BIP-39 entropy `0660cc198330660cc198330660cc1983`)
