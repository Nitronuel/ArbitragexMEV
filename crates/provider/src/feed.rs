//! Blocking Nitro sequencer-feed client (RHC broadcast protocol).
//!
//! Unlike [`crate::LiveWsClient`], the Nitro broadcast feed needs no
//! subscription message: the server streams sequencer messages from connect.
//! The socket lives on a reader thread forwarding raw text frames over an
//! in-process channel; batch decoding into pool-touch events lives in the
//! `shadow-bot` feed module so this crate stays transport-only.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

use tungstenite::Message;

use crate::{DisconnectKind, RedactedUrl, StreamError};

/// One frame moved from the reader thread to the owning thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedFrame {
    /// Raw broadcast text payload (JSON envelope, never parsed here).
    Text(String),
    /// Socket closed or failed; the owner reconnects.
    Closed(DisconnectKind),
}

/// Live Nitro feed backed by `tungstenite`, blocking like [`crate::LiveWsClient`].
pub struct FeedClient {
    rx: Receiver<FeedFrame>,
}

impl FeedClient {
    /// Connects to a Nitro broadcast feed endpoint.
    ///
    /// Installs the `ring` rustls crypto provider as the process default
    /// before spawning the reader thread (same dual-provider pitfall as
    /// [`crate::LiveWsClient::connect`]).
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::InvalidMessage`] when the reader thread cannot
    /// be started. Connect/read failures surface as [`FeedFrame::Closed`].
    pub fn connect(endpoint: RedactedUrl) -> Result<Self, StreamError> {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let (sender, receiver) = channel();
        thread::Builder::new()
            .name("nitro-feed".to_owned())
            .spawn(move || run_reader(&endpoint, &sender))
            .map_err(|_| StreamError::InvalidMessage)?;
        Ok(Self { rx: receiver })
    }

    /// Receives the next frame, returning `None` on timeout or when the
    /// reader thread is gone.
    #[must_use]
    pub fn next(&self, timeout: Duration) -> Option<FeedFrame> {
        self.rx.recv_timeout(timeout).ok()
    }
}

fn run_reader(endpoint: &RedactedUrl, tx: &Sender<FeedFrame>) {
    let Ok((mut socket, _)) = tungstenite::connect(endpoint.expose().as_str()) else {
        let _ = tx.send(FeedFrame::Closed(DisconnectKind::Dirty));
        return;
    };
    loop {
        match socket.read() {
            Ok(Message::Text(text)) => {
                if tx.send(FeedFrame::Text(text.to_string())).is_err() {
                    return;
                }
            }
            Ok(Message::Ping(payload)) => {
                let _ = socket.send(Message::Pong(payload));
            }
            Ok(Message::Pong(_) | Message::Binary(_) | Message::Frame(_)) => {}
            Ok(Message::Close(_)) => {
                let _ = tx.send(FeedFrame::Closed(DisconnectKind::Clean));
                return;
            }
            Err(_) => {
                let _ = tx.send(FeedFrame::Closed(DisconnectKind::Dirty));
                return;
            }
        }
    }
}
