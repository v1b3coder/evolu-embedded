# CLAUDE.md

Full design rationale, architecture diagrams, and protocol details: **[ARCHITECTURE.md](ARCHITECTURE.md)**

## What This Is

Pure Rust port of Evolu local-first CRDT sync, ported from `../packages/common/src/local-first/`. `evolu-core` is `no_std` for STM32U5 (Cortex-M33). Other crates are std-only.

## Quick Commands

```bash
cargo test                    # all unit tests (151 tests)
cargo test -p evolu-core      # just core
cargo test -p evolu-stream-store # just stream-store
cargo test -- --ignored       # integration (needs relay)
cargo build -p evolu-core --target thumbv8m.main-none-eabihf --no-default-features  # cross-compile
cargo run -p evolu-demo       # sync demo (wss://free.evoluhq.com)
```

## Coding Rules

- **`evolu-core` must stay `no_std`**: no `Vec`, `String`, `Box`, `HashMap`. Use `Buffer<'a>` and `heapless::Vec<T, N>`.
- **No `f64::fract()`** in no_std — use `(n as i64 as f64) != n`.
- **Protocol messages must be bit-exact** with TypeScript Evolu. Verify against TS test vectors if you change encoding.
- **All data at rest is `EncryptedDbChange`** — the host never sees plaintext.

## Key Naming

- `StorageBackend` — trait in evolu-core. Two impls: `FileStorage`, `StreamStorage`.
- `HostStore` — trait in evolu-stream-store. Implemented by `FileHost` (filesystem) and future `UsbHost`.
- `StreamStorage` — struct that implements `StorageBackend` using a `HostStore`.

## Protocol Compatibility Gotcha

Range upper bounds use a `TimestampsBuffer` where count = N ranges but only N-1 real timestamps (last is `InfiniteUpperBound` — only increments count, no data encoded). This is critical for wire compatibility.
