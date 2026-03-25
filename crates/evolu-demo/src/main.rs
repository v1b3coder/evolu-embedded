//! Evolu sync demo — two clients syncing via a real relay.
//!
//! Demonstrates both storage backends through the same `StorageBackend` trait:
//! - Client A: host-storage (streaming encrypted index + host data cache)
//! - Client B: flash-storage (simple in-memory Vec, no encryption)
//!
//! Both clients create a "Hello world" entry each run and sync with the relay.
//! On subsequent runs, each client picks up the other's data.
//!
//! ```text
//! cargo run -p evolu-demo [relay_url]
//! ```
//!
//! Default relay: ws://localhost:4000
//! Data directory: /tmp/evolu-demo/

use evolu_core::message::MessageBuilder;
use evolu_core::owner::derive_owner;
use evolu_core::protocol::*;
use evolu_core::relay::RelayClient;
use evolu_core::storage::StorageBackend;
use evolu_core::timestamp::timestamp_to_bytes;
use evolu_core::transport::Transport;
use evolu_core::types::*;
use evolu_file_store::FileStorage;
use evolu_std_platform::StdPlatform;
use evolu_stream_store::file_host::FileHost;
use evolu_stream_store::storage::StreamStorage;
use evolu_stream_store::trusted_state::{self, TrustedState};
use evolu_ws_transport::{base64url_encode, WsTransport};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DATA_DIR: &str = "/tmp/evolu-demo";

fn main() {
    let relay_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wss://free.evoluhq.com".to_string());

    println!("╔═══════════════════════════════════════════════╗");
    println!("║   Evolu Embedded Rust — Persistent Sync Demo   ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!();
    println!("Relay: {}", relay_url);
    println!("Data:  {}", DATA_DIR);

    let secret = load_or_create_secret();
    let owner = derive_owner(&secret);
    println!("Owner: {}", base64url_encode(&owner.id));
    println!();

    // ── Client A: host-storage backend ──────────────────────────

    std::thread::sleep(Duration::from_millis(111));
    println!("━━━ Client A (evolu-stream-store) ━━━");
    let storage_dir = PathBuf::from(DATA_DIR).join("client-a");
    let trusted_path = storage_dir.join("trusted_state.bin");

    let trusted = trusted_state::file::load(&trusted_path).unwrap_or_else(|| {
        println!("  Fresh trusted state");
        TrustedState::new(owner.encryption_key)
    });

    let host = FileHost::new(&storage_dir).unwrap();
    let mut storage_a = StreamStorage::new(host, StdPlatform, trusted);

    run_client("A", &relay_url, &owner, "aaaaaaaaaaaaaaaa", &mut storage_a);

    trusted_state::file::save(&trusted_path, storage_a.trusted_state()).unwrap();

    println!();

    // ── Client B: flash-storage backend ─────────────────────────

    std::thread::sleep(Duration::from_millis(111));
    println!("━━━ Client B (evolu-file-store) ━━━");
    let mut storage_b = load_or_create_file_storage();

    run_client("B", &relay_url, &owner, "bbbbbbbbbbbbbbbb", &mut storage_b);

    save_file_storage(&mut storage_b);

    println!();
    println!("Run again to see cross-client sync.");
    println!("  rm -r {} to reset.", DATA_DIR);
}

// ── Generic sync client ─────────────────────────────────────────

fn run_client<S: StorageBackend>(
    name: &str,
    relay_url: &str,
    owner: &evolu_core::owner::OwnerKeys,
    node_id_hex: &str,
    storage: &mut S,
) where
    S::Error: core::fmt::Debug,
{
    let before_count = storage.size().unwrap();

    if before_count > 0 {
        println!("  Local storage ({} entries):", before_count);
        print_entries(storage, before_count, &owner.encryption_key);
    } else {
        println!("  Local storage: empty");
    }

    // Create a new entry with current time
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let node_id = NodeId::from_hex(node_id_hex).unwrap();
    let ts = timestamp_to_bytes(&Timestamp::new(
        Millis::new(now_ms).unwrap(),
        Counter::new(0),
        node_id,
    ));

    let secs = now_ms / 1000;
    let ms = now_ms % 1000;
    let message = format!(
        "Hello world from Client {} at {:02}:{:02}:{:02}.{:03} UTC",
        name,
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        ms
    );

    // Build encrypted DbChange — this is the canonical format stored everywhere
    let encrypted_change = encrypt_change(
        &owner.encryption_key,
        &ts,
        "greeting",
        &node_id.0,
        &[("message", &message)],
    );

    // Store the encrypted DbChange locally (same format as relay)
    storage.insert(&ts, &encrypted_change).unwrap();
    println!("  Created: \"{}\"", message);

    // Connect and sync
    println!("  Syncing...");
    let mut ws = WsTransport::new(relay_url);
    ws.connect(&owner.id)
        .unwrap_or_else(|_| panic!("Client {}: relay connection failed", name));

    let mut client = RelayClient::new(&owner.id, &owner.encryption_key, Some(&owner.write_key));

    // Build initial request with our new message + storage state
    {
        let count = storage.size().unwrap();
        let mut builder = MessageBuilder::new_request(
            &owner.id,
            Some(&owner.write_key),
            SUBSCRIPTION_SUBSCRIBE,
        )
        .unwrap();
        builder.add_message(&ts, &encrypted_change).unwrap();

        let mut all_ts: Vec<TimestampBytes> = Vec::new();
        storage.iterate(0, count, &mut |t, _| { all_ts.push(*t); true }).unwrap();
        builder.add_timestamps_range(None, &all_ts).unwrap();

        let mut msg_buf = [0u8; 16384];
        let msg_len = builder.finalize(&mut msg_buf).unwrap();
        ws.send(&msg_buf[..msg_len]).unwrap();
    }

    // Set client state so on_message works
    client.start_sync(storage).unwrap();
    let _ = client.pending_send(); // discard auto-generated message

    // Multi-round sync loop
    let before_sync = storage.size().unwrap();
    let max_rounds = 10;

    for round in 0..max_rounds {
        ws.poll_timeout(&mut client, Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("Client {}: relay timeout (round {})", name, round));

        // Store received messages (batch insert — one index rewrite per round)
        let received_ts = client.received_timestamps().to_vec();
        let received_ch = client.received_changes().to_vec();
        let batch: Vec<(&TimestampBytes, &[u8])> = received_ts
            .iter()
            .enumerate()
            .map(|(i, ts)| {
                let data: &[u8] = if i < received_ch.len() {
                    &received_ch[i]
                } else {
                    &[]
                };
                (ts, data)
            })
            .collect();
        if !batch.is_empty() {
            storage.insert_batch(&batch).unwrap();
        }

        if client.is_synced() {
            if round > 0 {
                println!("  Synced in {} rounds", round + 1);
            }
            break;
        }

        // Build follow-up from response ranges
        client.continue_sync(storage).unwrap();

        if let Some(msg) = client.pending_send() {
            ws.send(msg).unwrap();
        } else {
            break;
        }
    }

    let actual_new = storage.size().unwrap() - before_sync;
    if actual_new > 0 {
        println!("  Received {} new entry/entries from relay", actual_new);
    }

    ws.disconnect();

    let final_count = storage.size().unwrap();
    println!("  Storage: {} entries", final_count);
    print_entries(storage, final_count, &owner.encryption_key);
}

// ── Display entries ─────────────────────────────────────────────

fn print_entries<S: StorageBackend>(
    storage: &mut S,
    count: u32,
    encryption_key: &[u8; 32],
) where
    S::Error: core::fmt::Debug,
{
    let mut timestamps: Vec<TimestampBytes> = Vec::new();
    storage
        .iterate(0, count, &mut |ts, _| {
            timestamps.push(*ts);
            true
        })
        .unwrap();

    for ts in &timestamps {
        match storage.read(ts) {
            Ok(Some(data)) if !data.is_empty() => {
                // All entries are stored as encrypted DbChange — decrypt to display
                match decrypt_db_change(encryption_key, data, ts) {
                    Ok(change) => {
                        if let Some(msg) = change.first_string() {
                            println!("    - {}", msg);
                        } else {
                            println!("    - [table: {}]", change.table_str());
                        }
                    }
                    Err(_) => println!("    - <{} bytes, undecryptable>", data.len()),
                }
            }
            Ok(Some(_)) | Ok(None) => println!("    - <no data>"),
            Err(_) => println!("    - <read error>"),
        }
    }
}

// ── Flash storage persistence ───────────────────────────────────

fn file_storage_path() -> PathBuf {
    PathBuf::from(DATA_DIR).join("client-b").join("storage.dat")
}

fn load_or_create_file_storage() -> FileStorage {
    let path = file_storage_path();
    if !path.exists() {
        println!("  Fresh file storage");
        return FileStorage::new();
    }

    let data = std::fs::read(&path).unwrap_or_default();
    if data.len() < 4 {
        return FileStorage::new();
    }

    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut storage = FileStorage::new();
    let mut offset = 4;

    for _ in 0..count {
        if offset + 16 + 4 > data.len() {
            break;
        }
        let mut ts = [0u8; 16];
        ts.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        let data_len =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if offset + data_len > data.len() {
            break;
        }
        let payload = &data[offset..offset + data_len];
        offset += data_len;
        storage.insert(&ts, payload).unwrap();
    }

    println!("  Loaded {} entries from file", storage.len());
    storage
}

fn save_file_storage(storage: &mut FileStorage) {
    let path = file_storage_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    let count = storage.len() as u32;
    let mut data = count.to_le_bytes().to_vec();

    let mut timestamps = Vec::new();
    storage
        .iterate(0, count, &mut |ts, _| {
            timestamps.push(*ts);
            true
        })
        .unwrap();

    for ts in &timestamps {
        data.extend_from_slice(ts);
        match storage.read(ts).unwrap() {
            Some(payload) => {
                data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                data.extend_from_slice(payload);
            }
            None => {
                data.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }

    std::fs::write(&path, &data).unwrap();
    println!("  Saved {} entries to file", count);
}

// ── Helpers ─────────────────────────────────────────────────────

fn load_or_create_secret() -> [u8; 32] {
    let path = PathBuf::from(DATA_DIR).join("owner_secret");
    std::fs::create_dir_all(DATA_DIR).unwrap();
    if path.exists() {
        let data = std::fs::read(&path).unwrap();
        if data.len() == 32 {
            let mut s = [0u8; 32];
            s.copy_from_slice(&data);
            println!("Loaded owner secret\n");
            return s;
        }
    }
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).unwrap();
    std::fs::write(&path, &s).unwrap();
    println!("Created new owner secret\n");
    s
}

fn encrypt_change(
    key: &[u8; 32],
    ts: &TimestampBytes,
    table: &str,
    id: &[u8; 8],
    columns: &[(&str, &str)],
) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).unwrap();
    let mut id16 = [0u8; 16];
    id16[..8].copy_from_slice(id);

    let mut encoded_cols: Vec<(&str, Vec<u8>)> = Vec::new();
    for &(name, value) in columns {
        let mut vbuf = [0u8; 512];
        let mut vb = Buffer::new(&mut vbuf);
        encode_varint(&mut vb, PVT_STRING).unwrap();
        encode_string(&mut vb, value).unwrap();
        encoded_cols.push((name, vb.written().to_vec()));
    }
    let col_refs: Vec<(&str, &[u8])> =
        encoded_cols.iter().map(|(n, v)| (*n, v.as_slice())).collect();

    let mut out = [0u8; 4096];
    let mut buf = Buffer::new(&mut out);
    encode_and_encrypt_db_change(
        key, &nonce, ts, table, &IdBytes(id16), &col_refs, true, None, &mut buf,
    )
    .unwrap();
    buf.written().to_vec()
}
