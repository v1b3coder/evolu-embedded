//! WebSocket transport for Evolu — connects directly to a real Evolu relay.
//!
//! This is a **demonstration/std transport** that connects to an Evolu relay
//! over WebSocket. On embedded hardware, the device would instead use USB
//! to talk to a host program that proxies to WebSocket.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use evolu_ws_transport::WsTransport;
//! use evolu_core::transport::Transport;
//!
//! let owner_id = [0u8; 16];
//! let mut ws = WsTransport::new("ws://localhost:4000");
//! ws.connect(&owner_id).unwrap();
//! ws.send(&[1, 2, 3]).unwrap();
//! ```

use evolu_core::transport::{
    ConnectionState, MessageHandler, Transport, TransportError,
};
use tungstenite::protocol::Message;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::WebSocket;

/// WebSocket transport connecting to an Evolu relay.
///
/// Wraps tungstenite's synchronous WebSocket client. The relay URL
/// is `ws://host:port` (or `wss://` for TLS). The `ownerId` query
/// parameter is appended automatically.
pub struct WsTransport {
    relay_url: String,
    socket: Option<WebSocket<MaybeTlsStream<std::net::TcpStream>>>,
    state: ConnectionState,
}

impl WsTransport {
    /// Create a new WebSocket transport.
    ///
    /// - `relay_url`: Base relay URL, e.g. `"ws://localhost:4000"` or `"wss://free.evoluhq.com"`
    pub fn new(relay_url: &str) -> Self {
        WsTransport {
            relay_url: relay_url.to_string(),
            socket: None,
            state: ConnectionState::Disconnected,
        }
    }

    /// Poll for one incoming message. Blocks until a message arrives or error.
    ///
    /// Delivers the message to the handler via `on_message()`.
    /// Returns `Ok(true)` if a message was delivered, `Ok(false)` if
    /// the connection was closed gracefully.
    pub fn poll(&mut self, handler: &mut dyn MessageHandler) -> Result<bool, TransportError> {
        let socket = self.socket.as_mut().ok_or(TransportError::NotConnected)?;

        match socket.read() {
            Ok(Message::Binary(data)) => {
                handler.on_message(&data).map_err(|_| TransportError::Other)?;
                Ok(true)
            }
            Ok(Message::Close(_)) => {
                self.state = ConnectionState::Disconnected;
                handler.on_state_change(ConnectionState::Disconnected);
                Ok(false)
            }
            Ok(Message::Ping(data)) => {
                // Respond to ping with pong
                let _ = socket.send(Message::Pong(data));
                Ok(true)
            }
            Ok(_) => {
                // Text, Pong, Frame — ignore
                Ok(true)
            }
            Err(tungstenite::Error::ConnectionClosed) => {
                self.state = ConnectionState::Disconnected;
                handler.on_state_change(ConnectionState::Disconnected);
                Ok(false)
            }
            Err(_) => {
                self.state = ConnectionState::Disconnected;
                handler.on_state_change(ConnectionState::Disconnected);
                Err(TransportError::Other)
            }
        }
    }

    /// Poll with a timeout. Returns `Ok(false)` if no message within the timeout.
    ///
    /// Uses `set_read_timeout` on the underlying TCP stream.
    pub fn poll_timeout(
        &mut self,
        handler: &mut dyn MessageHandler,
        timeout: std::time::Duration,
    ) -> Result<bool, TransportError> {
        let socket = self.socket.as_mut().ok_or(TransportError::NotConnected)?;

        // Set timeout on underlying stream
        match socket.get_ref() {
            MaybeTlsStream::Plain(stream) => {
                stream.set_read_timeout(Some(timeout)).ok();
            }
            _ => {}
        }

        let result = self.poll(handler);

        // Reset timeout
        if let Some(socket) = self.socket.as_mut() {
            match socket.get_ref() {
                MaybeTlsStream::Plain(stream) => {
                    stream.set_read_timeout(None).ok();
                }
                _ => {}
            }
        }

        match result {
            Err(TransportError::Other) => {
                // Could be a timeout — check if still connected
                if self.state == ConnectionState::Connected {
                    Ok(false)
                } else {
                    result
                }
            }
            other => other,
        }
    }

    /// Full sync cycle: send message, poll for response, deliver to handler.
    ///
    /// This is a convenience method for synchronous sync operations.
    /// Sends the message, then blocks waiting for a response.
    pub fn send_and_receive(
        &mut self,
        message: &[u8],
        handler: &mut dyn MessageHandler,
    ) -> Result<(), TransportError> {
        self.send(message)?;
        self.poll(handler)?;
        Ok(())
    }
}

impl Transport for WsTransport {
    fn connect(&mut self, owner_id: &[u8; 16]) -> Result<(), TransportError> {
        let base = self.relay_url.trim_end_matches('/');
        let owner_id_b64 = base64url_encode(owner_id);
        let full_url = format!("{}/?ownerId={}", base, owner_id_b64);

        self.state = ConnectionState::Connecting;

        match tungstenite::connect(&full_url) {
            Ok((socket, _response)) => {
                self.socket = Some(socket);
                self.state = ConnectionState::Connected;
                Ok(())
            }
            Err(e) => {
                #[cfg(feature = "std")]
                eprintln!("WebSocket connect error: {:?}", e);
                self.state = ConnectionState::Disconnected;
                Err(TransportError::ConnectionFailed)
            }
        }
    }

    fn disconnect(&mut self) {
        if let Some(ref mut socket) = self.socket {
            let _ = socket.close(None);
        }
        self.socket = None;
        self.state = ConnectionState::Disconnected;
    }

    fn state(&self) -> ConnectionState {
        self.state
    }

    fn send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        let socket = self.socket.as_mut().ok_or(TransportError::NotConnected)?;
        socket
            .send(Message::Binary(message.to_vec().into()))
            .map_err(|_| TransportError::SendFailed)?;
        Ok(())
    }
}

/// Base64url encode without padding (RFC 4648 §5).
pub fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_encode_16_bytes() {
        // 16 bytes → 22 characters (no padding)
        let bytes = [
            0x4a, 0xd6, 0xef, 0x75, 0x33, 0xf1, 0x93, 0xcd, 0x33, 0xd1, 0xc3, 0x55, 0xc0, 0x32,
            0x60, 0xea,
        ];
        let encoded = base64url_encode(&bytes);
        assert_eq!(encoded.len(), 22);
        // Verify round-trip would work (just check length and charset)
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn base64url_known_vectors() {
        assert_eq!(base64url_encode(&[]), "");
        assert_eq!(base64url_encode(&[0]), "AA");
        assert_eq!(base64url_encode(&[0, 0]), "AAA");
        assert_eq!(base64url_encode(&[0, 0, 0]), "AAAA");
        assert_eq!(base64url_encode(&[255, 255, 255]), "____");
    }

    #[test]
    fn ws_transport_creates_with_url() {
        let ws = WsTransport::new("ws://localhost:4000");
        assert_eq!(ws.state(), ConnectionState::Disconnected);
        assert_eq!(ws.relay_url, "ws://localhost:4000");
    }

    #[test]
    fn connect_to_nonexistent_relay() {
        let owner_id = [0u8; 16];
        let mut ws = WsTransport::new("ws://127.0.0.1:59999");
        let result = ws.connect(&owner_id);
        assert_eq!(result, Err(TransportError::ConnectionFailed));
        assert_eq!(ws.state(), ConnectionState::Disconnected);
    }

    // Integration test — only runs if a local relay is available.
    // Run with: cargo test --package evolu-ws-transport -- --ignored
    #[test]
    #[ignore]
    fn connect_to_local_relay() {
        use evolu_core::owner::derive_owner;
        use evolu_core::relay::RelayClient;
        use evolu_core::types::*;

        // Generate a fresh owner for this test
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let owner = derive_owner(&secret);

        println!("Owner ID (base64url): {}", base64url_encode(&owner.id));
        println!("Connecting to ws://localhost:4000...");

        let mut ws = WsTransport::new("ws://localhost:4000");
        ws.connect(&owner.id).expect("Failed to connect to local relay (is it running on port 4000?)");

        assert_eq!(ws.state(), ConnectionState::Connected);
        println!("Connected!");

        // Build initial sync request (empty storage)
        let mut client = RelayClient::new(&owner.id, &owner.encryption_key, None);
        let mut empty_storage = evolu_file_store::FileStorage::new();
        client.start_sync(&mut empty_storage).unwrap();

        let msg = client.pending_send().unwrap().to_vec();
        println!("Sending sync request ({} bytes)...", msg.len());

        // Send and receive
        ws.send(&msg).unwrap();
        println!("Waiting for relay response...");

        ws.poll_timeout(
            &mut client,
            std::time::Duration::from_secs(5),
        ).expect("Failed to receive response");

        println!("Sync state: {:?}", client.state());
        println!("Messages received: {}", client.messages_received());
        println!("Rounds: {}", client.rounds());

        assert!(
            client.is_synced(),
            "Expected sync to complete (empty storage should match empty relay). State: {:?}",
            client.state()
        );

        println!("Sync complete — empty storage matches relay.");
        ws.disconnect();
    }

    #[test]
    #[ignore]
    fn send_data_and_sync_with_second_client() {
        use evolu_core::message::MessageBuilder;
        use evolu_core::owner::derive_owner;
        use evolu_core::protocol::*;
        use evolu_core::relay::RelayClient;
        use evolu_core::timestamp::timestamp_to_bytes;
        use evolu_core::types::*;

        // Both clients share the same owner (same secret = same keys)
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let owner = derive_owner(&secret);

        println!("=== Test: Send data from client A, sync to client B ===");
        println!("Owner ID: {}", base64url_encode(&owner.id));

        // ── Client A: send a CRDT message to the relay ──────────

        println!("\n--- Client A: connecting and sending data ---");
        let mut ws_a = WsTransport::new("ws://localhost:4000");
        ws_a.connect(&owner.id).expect("Client A: connection failed");

        // Create a CRDT message
        let ts = timestamp_to_bytes(&Timestamp::new(
            Millis::new(1711234567890).unwrap(),
            Counter::new(0),
            NodeId::from_hex("deadbeef01234567").unwrap(),
        ));

        // Encode a DbChange: table="todo", one column "title"="Buy milk"
        // Pre-encode the value as PVT_STRING
        let mut val_buf = [0u8; 64];
        let mut vb = Buffer::new(&mut val_buf);
        encode_varint(&mut vb, PVT_STRING).unwrap();
        encode_string(&mut vb, "Buy milk").unwrap();
        let val_bytes = vb.written().to_vec();

        let id_bytes = IdBytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ]);

        // Encrypt the DbChange
        let mut enc_out = [0u8; 4096];
        let mut enc_buf = Buffer::new(&mut enc_out);
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).unwrap();
        encode_and_encrypt_db_change(
            &owner.encryption_key,
            &nonce,
            &ts,
            "todo",
            &id_bytes,
            &[("title", &val_bytes)],
            true,  // isInsert
            None,  // isDelete
            &mut enc_buf,
        ).unwrap();
        let encrypted_change = enc_buf.written().to_vec();

        // Build a protocol message with this CRDT message + a TimestampsRange
        let mut builder = MessageBuilder::new_request(
            &owner.id,
            Some(&owner.write_key),
            SUBSCRIPTION_SUBSCRIBE,
        ).unwrap();
        builder.add_message(&ts, &encrypted_change).unwrap();
        // Add a TimestampsRange with our single timestamp
        builder.add_timestamps_range(None, &[ts]).unwrap();

        let mut msg_buf = [0u8; 8192];
        let msg_len = builder.finalize(&mut msg_buf).unwrap();

        println!("Client A: sending {} bytes (1 message + 1 range)", msg_len);
        ws_a.send(&msg_buf[..msg_len]).unwrap();

        // Wait for relay response
        let mut client_a = RelayClient::new(&owner.id, &owner.encryption_key, Some(&owner.write_key));
        let mut empty_a = evolu_file_store::FileStorage::new();
        client_a.start_sync(&mut empty_a).unwrap();
        // Consume the auto-generated message (we already sent our manual one)
        let _ = client_a.pending_send();

        ws_a.poll_timeout(&mut client_a, std::time::Duration::from_secs(5))
            .expect("Client A: relay response timeout");

        println!("Client A: relay response received, state={:?}", client_a.state());

        ws_a.disconnect();
        println!("Client A: disconnected");

        // ── Client B: connect and sync — should receive the message ─

        println!("\n--- Client B: connecting and syncing ---");
        let mut ws_b = WsTransport::new("ws://localhost:4000");
        ws_b.connect(&owner.id).expect("Client B: connection failed");

        let mut client_b = RelayClient::new(&owner.id, &owner.encryption_key, Some(&owner.write_key));
        let mut empty_b = evolu_file_store::FileStorage::new();
        client_b.start_sync(&mut empty_b).unwrap();
        let sync_msg = client_b.pending_send().unwrap().to_vec();
        println!("Client B: sending sync request ({} bytes)", sync_msg.len());

        ws_b.send(&sync_msg).unwrap();
        ws_b.poll_timeout(&mut client_b, std::time::Duration::from_secs(5))
            .expect("Client B: relay response timeout");

        println!("Client B: state={:?}", client_b.state());
        println!("Client B: messages received = {}", client_b.messages_received());
        println!("Client B: ranges = {}", client_b.response_ranges().len());

        for (i, range) in client_b.response_ranges().iter().enumerate() {
            match range {
                evolu_core::relay::ParsedRange::Skip { .. } => println!("  Range {}: Skip", i),
                evolu_core::relay::ParsedRange::Fingerprint { fingerprint, .. } => {
                    println!("  Range {}: Fingerprint({:02x?})", i, &fingerprint[..4]);
                }
                evolu_core::relay::ParsedRange::Timestamps { timestamps, .. } => {
                    println!("  Range {}: Timestamps(count={})", i, timestamps.len());
                }
            }
        }

        // Client B should have received the message we sent from Client A
        assert!(
            client_b.messages_received() > 0,
            "Client B should have received messages from the relay (Client A sent 1)"
        );

        println!("\nClient B received {} message(s) from relay!", client_b.messages_received());

        ws_b.disconnect();
        println!("=== Test passed: data synced between two Rust clients via relay ===");
    }
}
