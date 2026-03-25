# Evolu Embedded — Rust Port Design Decisions

## Purpose

Minimal Evolu CRDT sync endpoint in pure Rust for STM32U5 (Cortex-M33) embedded hardware. Designed to sync with standard Evolu relays while operating under severe memory constraints.

`evolu-core` compiles for `thumbv8m.main-none-eabihf` (STM32U5 Cortex-M33) as `no_std`.

## Architecture

```
┌─ evolu-core (no_std) ─────────────────────────────────────┐
│                                                           │
│  Traits (implemented externally):                         │
│  ┌───────────────┐ ┌─────────────────────┐ ┌──────────┐  │
│  │StorageBackend │ │Transport +          │ │Platform  │  │
│  │               │ │  MessageHandler     │ │          │  │
│  └───────┬───────┘ └──────────┬──────────┘ └────┬─────┘  │
│          │                    │                  │        │
│  Internal modules (use the traits above):                │
│  ┌───────┴────────────────────┴──────────────────┴─────┐  │
│  │ relay.rs     ← sync session, drives the protocol    │  │
│  │ message.rs   ← builds wire-compatible messages      │  │
│  │ protocol.rs  ← binary codec, EncryptedDbChange      │  │
│  │ sync.rs      ← RBSR bucket computation              │  │
│  │ crdt.rs      ← LWW per-column merge                 │  │
│  │ timestamp.rs ← Hybrid Logical Clock                  │  │
│  │ crypto.rs    ← SLIP-21, PADME, SHA-256 fingerprints │  │
│  │ owner.rs     ← key derivation from OwnerSecret      │  │
│  │ types.rs     ← Millis, Counter, NodeId, Buffer       │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
        │                    │                  │
        ▼                    ▼                  ▼
  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐
  │evolu-stream-│   │evolu-ws-     │   │evolu-std-    │
  │  store      │   │  transport   │   │  platform    │
  │  (std)      │   │  (std)       │   │  (std)       │
  ├─────────────┤   ├──────────────┤   ├──────────────┤
  │evolu-file-  │   │USB CDC       │   │STM32U5 RTC + │
  │  store      │   │  (embedded)  │   │  TRNG        │
  │  (std)      │   │              │   │  (embedded)  │
  └─────────────┘   └──────────────┘   └──────────────┘
```

### Three core traits (evolu-core)

Everything in `evolu-core` is generic over three traits:

- **`StorageBackend`** — timestamp index + data retrieval
- **`Transport` + `MessageHandler`** — relay communication
- **`Platform`** — clock and randomness

```rust
pub trait StorageBackend {
    type Error: core::fmt::Debug;
    fn size(&mut self) -> Result<u32, Self::Error>;
    fn fingerprint(&mut self, begin: u32, end: u32) -> Result<Fingerprint, Self::Error>;
    fn iterate(&mut self, begin: u32, end: u32,
               cb: &mut dyn FnMut(&TimestampBytes, u32) -> bool) -> Result<(), Self::Error>;
    fn insert(&mut self, ts: &TimestampBytes, data: &[u8]) -> Result<(), Self::Error>;
    fn insert_batch(&mut self, entries: &[(&TimestampBytes, &[u8])]) -> Result<(), Self::Error>;
    fn read(&mut self, ts: &TimestampBytes) -> Result<Option<&[u8]>, Self::Error>;
}

pub trait Platform {
    fn now_millis(&self) -> u64;
    fn fill_random(&mut self, buf: &mut [u8]);
}
```

### Two storage models

**evolu-file-store** (`FileStorage`) — simple Vec-backed, std-only, for demo/testing:
- Blobs + index all in memory, serialized to a single file
- Self-contained, no external dependencies

**evolu-stream-store** (`StreamStorage`) — for untrusted USB host:
- Encrypted timestamp index: streaming chunks (AEAD per chunk)
- Blob cache: opaque `EncryptedDbChange` blobs stored on host
- 64 bytes on-chip trusted state for replay detection
- ~4 KB SRAM working set (two chunk buffers for streaming merge)

Both implement `StorageBackend`. The sync engine and application code are generic over the trait.

### HostStore trait (evolu-stream-store)

`StreamStorage` delegates to a `HostStore` — the interface to the untrusted host:

```rust
pub trait HostStore {
    type Error: core::fmt::Debug;

    // Encrypted index (streaming, device-managed)
    fn index_size(&mut self) -> Result<u64, Self::Error>;
    fn index_read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Error>;
    fn index_write_begin(&mut self) -> Result<(), Self::Error>;
    fn index_write_append(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn index_write_commit(&mut self) -> Result<(), Self::Error>;

    // Blob cache (opaque EncryptedDbChange, key-value)
    fn put_blob(&mut self, ts: &[u8; 16], data: &[u8]) -> Result<(), Self::Error>;
    fn get_blob(&mut self, ts: &[u8; 16], buf: &mut [u8]) -> Result<usize, Self::Error>;
}
```

The index is device-encrypted (XChaCha20-Poly1305 with `device_key`). The host can't read or tamper with it. Blobs are already protocol-encrypted (`EncryptedDbChange`) — the host stores them opaquely.

`index_write_begin` writes to a temporary location. The old index must remain readable via `index_read_at` until `index_write_commit` atomically replaces it. This enables streaming merge-insert.

**`FileHost`** implements `HostStore` backed by the filesystem (demo/testing). A future **`UsbHost`** would implement it over USB CDC.

### Data flow

Blobs enter the system through the `Transport` (sync receive or local creation) and are stored on the host via `put_blob`. The device reads them back via `get_blob` when materializing data. The host caches every blob that flows through — since the Evolu relay has no single-blob fetch API (only RBSR sync), cached blobs are the only way to retrieve data without a full re-sync.

```
Sync receive:  Relay → Transport → App → storage.insert(ts, data)
                                              → host.put_blob(ts, data)
                                              → merge ts into encrypted index

App reads:     storage.read(ts) → host.get_blob(ts)

New data:      App encrypts blob → storage.insert(ts, blob)
                                 → transport.send(message with blob)
```

### Streaming merge-insert

Inserting entries into the encrypted index uses a two-pass streaming merge:

1. **Pre-scan**: stream old index to count duplicates → compute `total_entries` for header
2. **Merge-write**: `IndexReader` reads old index one chunk at a time, `IndexWriter` writes new index one chunk at a time, merge cursor interleaves new entries in sorted order

RAM: ~4 KB (one read buffer + one write buffer, ~1936 bytes each). No ceiling on index size.

`insert_batch` processes multiple entries in a single merge-write, avoiding one full index rewrite per entry during sync.

### Crash safety

Index writes use `begin/append/commit` (atomic rename). If power is lost:

| Crash point | Recovery |
|---|---|
| During blob writes | Orphaned blobs, invisible (not in index) |
| During index tmp write | Old index intact, tmp discarded |
| After index commit, before flash write | `validate_and_recover` detects off-by-one sequence, auto-advances |
| After flash write | Fully consistent |

## On-chip Trusted State (64 bytes)

```
device_key:    [u8; 32]   — XChaCha20-Poly1305 key, never leaves the chip
dir_sequence:  u64         — sequence of last index write (replay detection)
clock:         [u8; 16]   — HLC timestamp state
```

On boot, `validate_and_recover` reads the index header and checks `dir_sequence`. Allows exactly `+1` to recover from the crash window between index commit and flash write.

## Timestamp Index (streamed)

```
header (36B):  sequence(8B) + nonce_seed(24B) + total_entries(4B)
chunk 0:       AEAD(entries[0..64]) + tag(16B)
chunk 1:       AEAD(entries[64..128]) + tag(16B)
...

Each entry (30 bytes):
  TimestampBytes:  [u8; 16]   — HLC timestamp (sorted key)
  Fingerprint:     [u8; 12]   — SHA-256(timestamp)[0..12] for RBSR sync
  page_id:         u16 LE     — reserved
```

- Device streams one chunk at a time (~1.9 KB), decrypts, processes entries, discards
- Each chunk authenticated with AAD = (sequence, chunk_index) — prevents reorder/truncation
- `total_entries` in header prevents the host from truncating the stream

## Transport Layer

Split into sending (active) and receiving (callback-based):

```rust
pub trait Transport {
    fn connect(&mut self, owner_id: &[u8; 16]) -> Result<(), TransportError>;
    fn disconnect(&mut self);
    fn state(&self) -> ConnectionState;
    fn send(&mut self, message: &[u8]) -> Result<(), TransportError>;
}

pub trait MessageHandler {
    fn on_message(&mut self, message: &[u8]) -> Result<(), HandleError>;
    fn on_state_change(&mut self, new_state: ConnectionState);
}
```

- No address in `connect()` — the host knows the relay endpoint. `owner_id` tells the host which owner to sync for.
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
│   │   ├── platform.rs          # Platform trait (clock + randomness)
│   │   ├── transport.rs         # Transport + MessageHandler traits, mock pair
│   │   ├── sync.rs              # RBSR bucket computation
│   │   └── relay.rs             # RelayClient (callback-driven sync)
│   │
│   ├── evolu-stream-store/      # Stream-storage backend (std)
│   │   ├── host.rs              # HostStore trait (index + blob cache)
│   │   ├── file_host.rs         # FileHost: HostStore backed by filesystem
│   │   ├── index.rs             # Streaming encrypted index, IndexReader,
│   │   │                        #   IndexWriter, merge, crash recovery
│   │   ├── storage.rs           # StreamStorage: StorageBackend implementation
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
│       └── src/main.rs          # Two clients syncing via real relay
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

Client A uses `StreamStorage` + `FileHost` (encrypted index + blob cache on filesystem).
Client B uses `FileStorage` (simple Vec in memory).
Both sync through the same relay using the same `StorageBackend` trait.

## Cross-compilation

```bash
# evolu-core compiles for STM32U5 (Cortex-M33)
rustup target add thumbv8m.main-none-eabihf
cargo build -p evolu-core --target thumbv8m.main-none-eabihf --no-default-features
```

## Testing

151 unit tests + 2 integration tests against a live relay.

```bash
cargo test                    # all unit tests
cargo test -- --ignored       # integration tests (needs running relay)
```

## Divergences from TypeScript Evolu

| Aspect | TypeScript | Rust embedded |
|---|---|---|
| Storage | SQLite with recursive CTE skiplist | Streaming index + blob cache on host |
| Query layer | Kysely (full SQL) | StorageBackend trait (7 methods) |
| Schema evolution | ALTER TABLE, column quarantine | Fixed schema |
| Owners | AppOwner, SharedOwner, ShardOwner | AppOwner only |
| SqliteValue encode | Full optimizations (DateIso, Id, Json...) | Simplified encode, full decode |
| Transport | WebSocket with auto-reconnect | Generic trait (USB CDC or WebSocket) |
| Data at rest | Plaintext in SQLite | Always EncryptedDbChange (AEAD) |

## Future Work

- **STM32U5 HAL**: USB CDC Transport + HostStore for real hardware
- **USB proxy host**: Host-side program bridging USB CDC ↔ WebSocket relay, with transparent blob caching
- **Store-and-forward**: Host queues unsent messages while offline, forwards when connectivity returns
