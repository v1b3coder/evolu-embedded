# Evolu Embedded — Rust Port Design Decisions

## Purpose

Minimal Evolu CRDT sync endpoint in pure Rust for STM32U5 (Cortex-M33) embedded hardware. Designed to sync with standard Evolu relays while operating under severe memory constraints.

`evolu-core` compiles for `thumbv8m.main-none-eabihf` (STM32U5 Cortex-M33) as `no_std`.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    evolu-core                        │
│         no_std, pure Rust, compiles for STM32U5     │
│                                                     │
│  StorageBackend trait    Transport trait             │
│  ┌──────────┐            ┌──────────┐               │
│  │          │            │          │               │
│  └────┬─────┘            └────┬─────┘               │
│       │                       │                     │
│  Protocol · Sync · Relay · Crypto · HLC · CRDT      │
└───────┼───────────────────────┼─────────────────────┘
        │                       │
   ┌────┴──────────┐     ┌─────┴──────────┐
   │ Storage       │     │ Transport      │
   │ backends      │     │ implementations│
   ├───────────────┤     ├────────────────┤
   │evolu-page-    │     │evolu-ws-       │
   │  store (std)  │     │  transport(std)│
   │               │     │                │
   │evolu-file-    │     │USB CDC         │
   │  storage (std)│     │  (embedded)    │
   └───────────────┘     └────────────────┘
```

### Two storage models

The `StorageBackend` trait abstracts storage. Two implementations exist:

```rust
pub trait StorageBackend {
    type Error: core::fmt::Debug;
    fn size(&mut self) -> Result<u32, Self::Error>;
    fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, Self::Error>;
    fn iterate(&mut self, begin: u32, end: u32,
               cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool) -> Result<(), Self::Error>;
    fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), Self::Error>;
    fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, Self::Error>;
}
```

**evolu-stream-store** — for untrusted USB host:
- Timestamp index: streaming encrypted chunks (AEAD per chunk, signed)
- Data: cached on host as raw EncryptedDbChange blobs (already AEAD by protocol)
- 64 bytes on-chip trusted state for replay detection
- Designed for ~2.5 KB SRAM working set

**evolu-file-store** — simple Vec-backed demo/testing:
- Everything in memory, serialized to a single file
- No encryption, no streaming
- std only

### Data format

All data — whether created locally or received from a relay — is stored as `EncryptedDbChange` blobs. This is the native Evolu protocol format. The same bytes can be:
- Stored in the host cache
- Forwarded to the relay
- Decrypted by any device with the owner's encryption key

The host never sees plaintext. Even the timestamp index is encrypted in chunks.

### Host as store-and-forward cache

The USB host acts as both a storage proxy and a network proxy:

1. **Storage**: holds the encrypted index + data cache. The device streams the index over USB and reads/writes cache entries by timestamp key.
2. **Network**: forwards protocol messages to/from the Evolu relay over WebSocket. If offline, the host queues messages and forwards them when connectivity returns.
3. **Cache**: transparently caches relay responses. The device doesn't know whether data came from cache or the live relay — both are verified by AEAD.

The host cannot read, modify, or forge any data. It's a blind pipe.

## On-chip Trusted State (64 bytes)

```
device_key:    [u8; 32]   — XChaCha20-Poly1305 key, never leaves the chip
dir_sequence:  u64         — sequence of last index write (replay detection)
clock:         [u8; 16]   — HLC timestamp state
```

On boot, the device reads the index header from the host and checks that the embedded sequence matches `dir_sequence`. If the host replays an older index, the sequence is lower → rejected.

## Timestamp Index (streamed)

```
header (36B):  sequence(8B) + nonce_seed(24B) + total_entries(4B)
chunk 0:       AEAD(entries[0..64]) + tag(16B)
chunk 1:       AEAD(entries[64..128]) + tag(16B)
...

Each entry (28 bytes):
  TimestampBytes:  [u8; 16]   — HLC timestamp (sorted key)
  Fingerprint:     [u8; 12]   — SHA-256(timestamp)[0..12] for RBSR sync
```

- Device streams one chunk at a time (~1.8 KB), decrypts, processes entries, discards
- RAM per entry: 28 bytes. No ceiling on total entries.
- Each chunk authenticated with AAD = (sequence, chunk_index) — prevents reorder/truncation
- `total_entries` in header prevents the host from truncating the stream

## Transport Layer

Split into sending (active) and receiving (callback-based):

```rust
pub trait Transport {
    fn connect(&mut self) -> Result<(), TransportError>;
    fn disconnect(&mut self);
    fn state(&self) -> ConnectionState;
    fn send(&mut self, message: &[u8]) -> Result<(), TransportError>;
}

pub trait MessageHandler {
    fn on_message(&mut self, message: &[u8]) -> Result<(), HandleError>;
    fn on_state_change(&mut self, new_state: ConnectionState);
}
```

- No address in `connect()` — the host knows the relay endpoint
- Callback receive — the host pushes messages (interrupt-driven), no polling
- `RelayClient` implements `MessageHandler` — wire to transport and sync runs automatically

## Protocol Compatibility

Bit-exact compatible with TypeScript Evolu. Verified against test vectors:

| Component | Verification |
|---|---|
| Varint encoding | 14 exact byte-array vectors |
| MessagePack numbers | 57-byte concatenated snapshot |
| SLIP-21 key derivation | Known mnemonic → known hex outputs |
| PADME padding | 29 input/output pairs |
| Protocol header | 24-byte snapshot matching TS |
| HLC send/receive | All branch vectors |
| EncryptedDbChange | Round-trip + tamper detection |

Integration tested against `wss://free.evoluhq.com` — the public Evolu relay.

## Crate Structure

```
evolu-embedded/
├── crates/
│   ├── evolu-core/              # no_std, compiles for thumbv8m.main-none-eabihf
│   │   ├── types.rs             # Millis, Counter, NodeId, Buffer, Fingerprint
│   │   ├── timestamp.rs         # Hybrid Logical Clock
│   │   ├── crypto.rs            # SLIP-21, PADME, SHA-256 fingerprints
│   │   ├── owner.rs             # Key derivation from OwnerSecret
│   │   ├── protocol.rs          # Binary codec + EncryptedDbChange encrypt/decrypt
│   │   ├── message.rs           # Wire-compatible protocol message builder
│   │   ├── crdt.rs              # LWW per-column merge logic
│   │   ├── storage.rs           # StorageBackend trait definition
│   │   ├── transport.rs         # Transport + MessageHandler traits, mock pair
│   │   ├── sync.rs              # RBSR bucket computation
│   │   └── relay.rs             # RelayClient (callback-driven sync)
│   │
│   ├── evolu-stream-store/        # Host-storage backend (std)
│   │   ├── host.rs              # HostInterface trait (index streaming + data cache)
│   │   ├── file_host.rs         # FileHost: HostInterface backed by filesystem
│   │   ├── index.rs             # Streaming encrypted index (chunk-based AEAD)
│   │   ├── storage.rs           # HostStorage: StorageBackend implementation
│   │   └── trusted_state.rs     # On-chip trusted state (64 bytes)
│   │
│   ├── evolu-file-store/        # File-storage backend (std, demo/testing)
│   │   └── lib.rs               # FileStorage: simple Vec-backed StorageBackend
│   │
│   ├── evolu-std-platform/      # Platform implementation (std)
│   │   └── lib.rs               # StdPlatform: SystemTime + getrandom
│   │
│   ├── evolu-ws-transport/      # WebSocket transport (std, demo/testing)
│   │   └── lib.rs               # WsTransport: tungstenite WebSocket + TLS
│   │
│   └── evolu-demo/              # Demo binary — wires everything together
│       └── src/main.rs           # Two clients syncing via real relay
```

## Dependencies

**evolu-core** (no_std):

| Crate | Purpose |
|---|---|
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD |
| `sha2` | SHA-256 for fingerprints |
| `hmac` | HMAC-SHA512 for SLIP-21 |
| `heapless` | Fixed-size Vec for no_std |

No MessagePack crate — minimal subset inline. No BIP-39 — accepts raw 32-byte OwnerSecret.

**std crates** (demo/testing): `tungstenite` (WebSocket + TLS), `getrandom`, `tempfile`.

## Running the Demo

```bash
# Two clients sync "Hello world" entries through the public Evolu relay
cargo run -p evolu-demo

# Or specify a local relay
cargo run -p evolu-demo -- ws://localhost:4000

# Reset state
rm -r /tmp/evolu-demo
```

Client A uses `evolu-stream-store` (encrypted index + host cache).
Client B uses `evolu-file-store` (simple Vec in memory).
Both sync through the same relay using the same `StorageBackend` trait.

## Cross-compilation

```bash
# evolu-core compiles for STM32U5 (Cortex-M33)
rustup target add thumbv8m.main-none-eabihf
cargo build -p evolu-core --target thumbv8m.main-none-eabihf --no-default-features
```

## Testing

124 unit tests + 2 integration tests against a live relay.

```bash
cargo test                    # all unit tests
cargo test -- --ignored       # integration tests (needs running relay)
```

## Divergences from TypeScript Evolu

| Aspect | TypeScript | Rust embedded |
|---|---|---|
| Storage | SQLite with recursive CTE skiplist | Streaming index + host cache |
| Query layer | Kysely (full SQL) | StorageBackend trait (5 methods) |
| Schema evolution | ALTER TABLE, column quarantine | Fixed schema |
| Owners | AppOwner, SharedOwner, ShardOwner | AppOwner only |
| SqliteValue encode | Full optimizations (DateIso, Id, Json...) | Simplified encode, full decode |
| Transport | WebSocket with auto-reconnect | Generic trait (USB CDC or WebSocket) |
| Data at rest | Plaintext in SQLite | Always EncryptedDbChange (AEAD) |

## Future Work

- **Multi-round RBSR**: Full range-based set reconciliation loop (single round works today)
- **STM32U5 HAL**: USB CDC Transport + HostInterface for real hardware
- **USB proxy host**: Host-side program bridging USB CDC ↔ WebSocket relay
- **Store-and-forward**: Host queues unsent messages while offline, forwards when connectivity returns
