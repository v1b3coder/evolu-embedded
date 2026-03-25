//! Generic transport interface for Evolu sync protocol.
//!
//! The transport abstracts the network layer between an embedded device
//! and an Evolu relay. The host knows the relay endpoint — the device
//! doesn't need to specify an address.
//!
//! ## Callback-based receive
//!
//! The host proactively notifies the device when a message arrives.
//! Instead of polling, the device registers an `on_message` callback
//! that the transport invokes when data is available. This matches
//! the embedded interrupt-driven model and avoids busy-waiting.
//!
//! ## Implementations
//!
//! - USB → host → Internet (embedded production)
//! - Mock (testing, direct message passing)

/// Transport connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

/// Transport errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Not connected to the relay.
    NotConnected,
    /// Connection failed.
    ConnectionFailed,
    /// Send failed.
    SendFailed,
    /// Transport-specific error.
    Other,
}

/// Generic transport interface for sending binary protocol messages.
///
/// Receiving is callback-based: the transport calls a handler when
/// a message arrives from the relay. The host knows the relay endpoint,
/// so `connect()` takes no address.
///
/// ## Lifecycle
///
/// ```text
/// connect() → [Connected] → send() / on_message callback → disconnect()
/// ```
pub trait Transport {
    /// Connect to the relay for the given owner.
    ///
    /// The host knows the network endpoint — the device doesn't need
    /// to specify an address. The `owner_id` tells the host which owner
    /// to connect for, so the host can independently sync with the relay
    /// (e.g., cache data while the device is disconnected).
    fn connect(&mut self, owner_id: &[u8; 16]) -> Result<(), TransportError>;

    /// Disconnect from the relay.
    fn disconnect(&mut self);

    /// Current connection state.
    fn state(&self) -> ConnectionState;

    /// Send a complete protocol message to the relay.
    fn send(&mut self, message: &[u8]) -> Result<(), TransportError>;
}

/// Handler invoked by the transport when a message arrives from the relay.
///
/// The device registers this callback. When the host receives a relay
/// message (proactively pushed or as a response), it notifies the device,
/// which invokes this handler.
///
/// The handler receives raw message bytes and returns whether processing
/// succeeded (so the transport can retry or log errors).
pub trait MessageHandler {
    /// Called when a complete protocol message arrives from the relay.
    ///
    /// `message` contains the raw bytes of a complete Evolu protocol message.
    /// Returns `Ok(())` if the message was processed successfully.
    fn on_message(&mut self, message: &[u8]) -> Result<(), HandleError>;

    /// Called when the connection state changes.
    fn on_state_change(&mut self, new_state: ConnectionState);
}

/// Errors from message handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandleError {
    /// Message parsing failed.
    ParseError,
    /// Storage operation failed during message processing.
    StorageError,
    /// Message was too large to process.
    TooLarge,
    /// Protocol version mismatch — relay uses a different version.
    VersionMismatch,
    /// Relay rejected the write key.
    WriteKeyError,
    /// Relay write failed.
    WriteError,
    /// Relay quota exceeded.
    QuotaError,
    /// Relay sync error.
    SyncError,
}

/// Mock transport for testing.
///
/// Pairs two mock transports together. Messages sent on one side are
/// delivered to the other side's handler. Call `deliver_pending()` to
/// simulate the host forwarding messages.
#[cfg(any(test, feature = "std"))]
pub mod mock {
    use super::*;
    extern crate alloc;
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// Shared message queue between paired transports.
    pub type MessageQueue = alloc::sync::Arc<RefCell<VecDeque<Vec<u8>>>>;

    fn new_queue() -> MessageQueue {
        alloc::sync::Arc::new(RefCell::new(VecDeque::new()))
    }

    /// Create a pair of connected mock transports.
    ///
    /// Messages sent on `a` are queued for `b`, and vice versa.
    /// Call `deliver_pending()` on a side to invoke its handler with
    /// all queued messages from the other side.
    pub fn create_mock_pair() -> (MockTransport, MockTransport) {
        let a_to_b = new_queue();
        let b_to_a = new_queue();

        (
            MockTransport {
                outbox: a_to_b.clone(),
                inbox: b_to_a.clone(),
                state: ConnectionState::Disconnected,
            },
            MockTransport {
                outbox: b_to_a,
                inbox: a_to_b,
                state: ConnectionState::Disconnected,
            },
        )
    }

    /// Mock transport for testing.
    pub struct MockTransport {
        outbox: MessageQueue,
        inbox: MessageQueue,
        state: ConnectionState,
    }

    impl MockTransport {
        /// Inject a message directly into this transport's receive queue.
        pub fn inject_message(&self, message: &[u8]) {
            self.inbox.borrow_mut().push_back(message.to_vec());
        }

        /// Number of messages waiting to be delivered to this side.
        pub fn pending_count(&self) -> usize {
            self.inbox.borrow().len()
        }

        /// Check if there are messages waiting.
        pub fn has_message(&self) -> bool {
            !self.inbox.borrow().is_empty()
        }

        /// Deliver all pending messages to the handler.
        ///
        /// This simulates the host proactively notifying the device.
        /// Returns the number of messages delivered.
        pub fn deliver_pending(
            &mut self,
            handler: &mut dyn MessageHandler,
        ) -> usize {
            let mut count = 0;
            loop {
                let msg = self.inbox.borrow_mut().pop_front();
                match msg {
                    Some(data) => {
                        let _ = handler.on_message(&data);
                        count += 1;
                    }
                    None => break,
                }
            }
            count
        }

        /// Deliver exactly one pending message to the handler.
        /// Returns true if a message was delivered.
        pub fn deliver_one(
            &mut self,
            handler: &mut dyn MessageHandler,
        ) -> bool {
            let msg = self.inbox.borrow_mut().pop_front();
            match msg {
                Some(data) => {
                    let _ = handler.on_message(&data);
                    true
                }
                None => false,
            }
        }

        /// Drain all sent messages (from this transport's outbox).
        pub fn drain_sent(&self) -> Vec<Vec<u8>> {
            self.outbox.borrow_mut().drain(..).collect()
        }
    }

    impl Transport for MockTransport {
        fn connect(&mut self, _owner_id: &[u8; 16]) -> Result<(), TransportError> {
            self.state = ConnectionState::Connected;
            Ok(())
        }

        fn disconnect(&mut self) {
            self.state = ConnectionState::Disconnected;
        }

        fn state(&self) -> ConnectionState {
            self.state
        }

        fn send(&mut self, message: &[u8]) -> Result<(), TransportError> {
            if self.state != ConnectionState::Connected {
                return Err(TransportError::NotConnected);
            }
            self.outbox.borrow_mut().push_back(message.to_vec());
            Ok(())
        }
    }

    /// A simple message collector for testing.
    /// Implements MessageHandler by storing all received messages.
    pub struct MessageCollector {
        pub messages: Vec<Vec<u8>>,
        pub state_changes: Vec<ConnectionState>,
    }

    impl MessageCollector {
        pub fn new() -> Self {
            MessageCollector {
                messages: Vec::new(),
                state_changes: Vec::new(),
            }
        }
    }

    impl MessageHandler for MessageCollector {
        fn on_message(&mut self, message: &[u8]) -> Result<(), HandleError> {
            self.messages.push(message.to_vec());
            Ok(())
        }

        fn on_state_change(&mut self, new_state: ConnectionState) {
            self.state_changes.push(new_state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::mock::*;

    #[test]
    fn mock_pair_send_and_deliver() {
        let (mut a, mut b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();
        b.connect(&[0u8; 16]).unwrap();

        a.send(b"hello from a").unwrap();
        b.send(b"hello from b").unwrap();

        let mut collector_b = MessageCollector::new();
        let delivered = b.deliver_pending(&mut collector_b);
        assert_eq!(delivered, 1);
        assert_eq!(collector_b.messages[0], b"hello from a");

        let mut collector_a = MessageCollector::new();
        let delivered = a.deliver_pending(&mut collector_a);
        assert_eq!(delivered, 1);
        assert_eq!(collector_a.messages[0], b"hello from b");
    }

    #[test]
    fn mock_not_connected() {
        let (mut a, _b) = create_mock_pair();
        assert_eq!(a.send(b"test"), Err(TransportError::NotConnected));
    }

    #[test]
    fn mock_no_pending_messages() {
        let (mut a, _b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();

        let mut collector = MessageCollector::new();
        assert_eq!(a.deliver_pending(&mut collector), 0);
        assert!(collector.messages.is_empty());
    }

    #[test]
    fn mock_fifo_ordering() {
        let (mut a, mut b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();
        b.connect(&[0u8; 16]).unwrap();

        a.send(b"first").unwrap();
        a.send(b"second").unwrap();
        a.send(b"third").unwrap();

        let mut collector = MessageCollector::new();
        b.deliver_pending(&mut collector);
        assert_eq!(collector.messages.len(), 3);
        assert_eq!(collector.messages[0], b"first");
        assert_eq!(collector.messages[1], b"second");
        assert_eq!(collector.messages[2], b"third");
    }

    #[test]
    fn mock_deliver_one() {
        let (mut a, mut b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();
        b.connect(&[0u8; 16]).unwrap();

        a.send(b"msg1").unwrap();
        a.send(b"msg2").unwrap();

        let mut collector = MessageCollector::new();
        assert!(b.deliver_one(&mut collector));
        assert_eq!(collector.messages.len(), 1);
        assert_eq!(collector.messages[0], b"msg1");

        // Second message still pending
        assert!(b.has_message());
        assert!(b.deliver_one(&mut collector));
        assert_eq!(collector.messages[1], b"msg2");

        // No more
        assert!(!b.deliver_one(&mut collector));
    }

    #[test]
    fn mock_inject_message() {
        let (mut a, _b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();

        a.inject_message(b"injected relay response");

        let mut collector = MessageCollector::new();
        a.deliver_pending(&mut collector);
        assert_eq!(collector.messages[0], b"injected relay response");
    }

    #[test]
    fn mock_disconnect_and_reconnect() {
        let (mut a, mut b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();
        b.connect(&[0u8; 16]).unwrap();

        a.send(b"before").unwrap();
        a.disconnect();
        assert_eq!(a.state(), ConnectionState::Disconnected);
        assert!(a.send(b"fails").is_err());

        // Message sent before disconnect is still queued
        let mut collector = MessageCollector::new();
        b.deliver_pending(&mut collector);
        assert_eq!(collector.messages[0], b"before");

        // Reconnect works
        a.connect(&[0u8; 16]).unwrap();
        a.send(b"after").unwrap();
        b.deliver_pending(&mut collector);
        assert_eq!(collector.messages[1], b"after");
    }

    #[test]
    fn mock_has_message() {
        let (mut a, mut b) = create_mock_pair();
        a.connect(&[0u8; 16]).unwrap();
        b.connect(&[0u8; 16]).unwrap();

        assert!(!b.has_message());
        a.send(b"test").unwrap();
        assert!(b.has_message());
        assert_eq!(b.pending_count(), 1);

        let mut collector = MessageCollector::new();
        b.deliver_pending(&mut collector);
        assert!(!b.has_message());
        assert_eq!(b.pending_count(), 0);
    }
}
