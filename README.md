# Evolu Embedded

Pure Rust port of the [Evolu](https://github.com/evoluhq/evolu) local-first CRDT sync protocol, targeting STM32U5 (Cortex-M33) embedded hardware.

The core crate is `no_std` and compiles for `thumbv8m.main-none-eabihf` with ~4 KB SRAM working set. It syncs with standard Evolu relays using the same wire protocol as the TypeScript implementation — bit-exact, verified against test vectors.

## Status

**Working today:**

- Full RBSR (Range-Based Set Reconciliation) sync with multi-round convergence
- `EncryptedDbChange` encrypt/decrypt (XChaCha20-Poly1305)
- SLIP-21 key derivation, PADME padding, SHA-256 fingerprints
- Hybrid Logical Clock (HLC) timestamps
- LWW (Last-Writer-Wins) per-column CRDT merge
- Wire-compatible protocol messages (varint, MessagePack numbers, binary codec)
- Streaming encrypted index with chunk-based AEAD and replay detection
- Streaming merge-insert (~4 KB RAM, no ceiling on index size)
- Crash-safe index writes with boot-time recovery
- Batch insert for efficient sync rounds
- 151 unit tests + 2 integration tests against a live relay

**Not yet implemented:**

- STM32U5 HAL (USB CDC Transport + HostStore for real hardware)
- USB proxy host (host-side program bridging USB CDC to WebSocket relay)
- Store-and-forward (host queues unsent messages while offline)

## Crates

| Crate | `no_std` | Purpose |
|---|---|---|
| `evolu-core` | yes | CRDT sync protocol, traits, codec |
| `evolu-stream-store` | | Streaming encrypted index + blob cache on host |
| `evolu-file-store` | | Simple Vec-backed storage for demo/testing |
| `evolu-std-platform` | | `Platform` impl: SystemTime + getrandom |
| `evolu-ws-transport` | | WebSocket transport via tungstenite |
| `evolu-demo` | | Two clients syncing through a real relay |

## Quick Start

```bash
# Run all tests
cargo test

# Run the sync demo (two clients sync through the public Evolu relay)
cargo run -p evolu-demo

# Use a local relay instead
cargo run -p evolu-demo -- ws://localhost:4000

# Cross-compile core for STM32U5
rustup target add thumbv8m.main-none-eabihf
cargo build -p evolu-core --target thumbv8m.main-none-eabihf --no-default-features

# Reset demo state
rm -r /tmp/evolu-demo
```

The demo creates two clients — one using `evolu-stream-store` (`StreamStorage` with encrypted streaming index + blob cache), the other using `evolu-file-store` (`FileStorage`, simple Vec in memory) — and syncs them through `wss://free.evoluhq.com`. Data persists across runs.

## Architecture

Everything in `evolu-core` is generic over three traits:

- **`StorageBackend`** — where is my data?
- **`Transport` + `MessageHandler`** — how do I talk to the relay?
- **`Platform`** — clock and randomness

Each trait has std implementations for desktop and will have embedded implementations for STM32U5. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design — trait definitions, storage models, wire format, on-chip trusted state, and protocol compatibility details.

## Relation to Evolu

This is a from-scratch Rust port of the sync protocol from [evoluhq/evolu](https://github.com/evoluhq/evolu) (specifically `packages/common/src/local-first/`). It does **not** port the query layer (Kysely/SQLite), schema evolution, or multi-owner support. The scope is: receive encrypted changes, merge them, send encrypted changes — enough for a sensor or hardware wallet to participate in the Evolu sync network.

Protocol compatibility is verified against exact byte arrays from the TypeScript test suite.

## License

MIT
