//! A bounded, blocking WebSocket client that subscribes to one filtered log
//! stream. The socket lives on a reader thread delivering decoded `Sync` payloads
//! over an in-process channel so the owning thread can bound the observation
//! window with `recv_timeout` without any async runtime.

use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tungstenite::Message;

use crate::{DisconnectKind, LogStream, RedactedUrl, StreamError, StreamItem, SubscriptionFilter};

/// Capable of dispatching a bounded WebSocket observation window.
pub trait WsProbe {
    /// Consumes the next item, returning `Ok(None)` once the bounded window
    /// elapses without a message or the subscription closes.
    ///
    /// # Errors
    ///
    /// Delegates to [`LogStream::message`] parsing and budget errors.
    fn next(
        &self,
        stream: &LogStream,
        timeout: Duration,
    ) -> Result<Option<StreamItem>, StreamError>;
}

/// One message moved from the reader thread to the owning thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsFrame {
    Text(String),
    Closed(DisconnectKind),
}

/// Live [`WsProbe`] backed by `tungstenite`.
pub struct LiveWsClient {
    rx: Receiver<WsFrame>,
}

impl LiveWsClient {
    /// Connects and subscribes the given filter over WebSocket.
    ///
    /// # Errors
    ///
    /// Returns an error when the reader thread cannot be started or the
    /// subscription is rejected by the endpoint.
    pub fn connect(endpoint: RedactedUrl, filter: SubscriptionFilter) -> Result<Self, StreamError> {
        let (sender, receiver) = channel();
        thread::Builder::new()
            .name("base-ws".to_owned())
            .spawn(move || run_reader(&endpoint, &filter, &sender))
            .map_err(|_| StreamError::InvalidMessage)?;
        Ok(Self { rx: receiver })
    }
}

impl WsProbe for LiveWsClient {
    fn next(
        &self,
        stream: &LogStream,
        timeout: Duration,
    ) -> Result<Option<StreamItem>, StreamError> {
        match self.rx.recv_timeout(timeout) {
            Ok(WsFrame::Text(text)) => stream.message(&text).map(Some),
            Ok(WsFrame::Closed(kind)) => Ok(Some(StreamItem::Disconnected(kind))),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Ok(None),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SubscriptionOutcome {
    Ack,
    Error,
}

fn subscription_outcome(text: &str) -> Option<SubscriptionOutcome> {
    let value: Value = serde_json::from_str(text).ok()?;
    if value.get("id") != Some(&json!(1)) {
        return None;
    }
    if value.get("error").is_some() {
        return Some(SubscriptionOutcome::Error);
    }
    if value.get("result").is_some() {
        return Some(SubscriptionOutcome::Ack);
    }
    None
}

fn is_subscription_notification(text: &str) -> bool {
    serde_json::from_str::<Value>(text)
        .is_ok_and(|value| value.get("method").and_then(Value::as_str) == Some("eth_subscription"))
}

fn run_reader(endpoint: &RedactedUrl, filter: &SubscriptionFilter, tx: &Sender<WsFrame>) {
    let Ok(request) = filter.request() else {
        let _ = tx.send(WsFrame::Closed(DisconnectKind::Dirty));
        return;
    };
    let Ok((mut socket, _)) = tungstenite::connect(endpoint.expose().as_str()) else {
        let _ = tx.send(WsFrame::Closed(DisconnectKind::Dirty));
        return;
    };
    let subscribe =
        json!({"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe", "params": request})
            .to_string();
    if socket.send(Message::Text(subscribe.into())).is_err() {
        let _ = tx.send(WsFrame::Closed(DisconnectKind::Dirty));
        return;
    }
    // Consume frames until the subscription acknowledgement.
    loop {
        match socket.read() {
            Ok(Message::Text(text)) => match subscription_outcome(text.as_str()) {
                Some(SubscriptionOutcome::Ack) => break,
                Some(SubscriptionOutcome::Error) => {
                    let _ = tx.send(WsFrame::Closed(DisconnectKind::Dirty));
                    return;
                }
                None => {}
            },
            Ok(Message::Ping(payload)) => {
                let _ = socket.send(Message::Pong(payload));
            }
            Ok(Message::Pong(_) | Message::Binary(_) | Message::Frame(_)) => {}
            Ok(Message::Close(_)) => {
                let _ = tx.send(WsFrame::Closed(DisconnectKind::Clean));
                return;
            }
            Err(_) => {
                let _ = tx.send(WsFrame::Closed(DisconnectKind::Dirty));
                return;
            }
        }
    }
    // Forward subscription notifications only.
    loop {
        match socket.read() {
            Ok(Message::Text(text)) if is_subscription_notification(text.as_str()) => {
                if tx.send(WsFrame::Text(text.to_string())).is_err() {
                    return;
                }
            }
            Ok(Message::Text(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_)) => {}
            Ok(Message::Ping(payload)) => {
                let _ = socket.send(Message::Pong(payload));
            }
            Ok(Message::Close(_)) => {
                let _ = tx.send(WsFrame::Closed(DisconnectKind::Clean));
                return;
            }
            Err(_) => {
                let _ = tx.send(WsFrame::Closed(DisconnectKind::Dirty));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_outcome_handles_ack_error_and_notifications() {
        assert!(matches!(
            subscription_outcome(r#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#),
            Some(SubscriptionOutcome::Ack)
        ));
        assert!(matches!(
            subscription_outcome(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}"#
            ),
            Some(SubscriptionOutcome::Error)
        ));
        assert_eq!(
            subscription_outcome(
                r#"{"jsonrpc":"2.0","method":"eth_subscription","params":{"result":{}}}"#
            ),
            None
        );
    }

    #[test]
    fn notification_detection_ignores_ack() {
        assert!(is_subscription_notification(
            r#"{"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"0x1","result":{}}}"#
        ));
        assert!(!is_subscription_notification(
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#
        ));
    }
}
