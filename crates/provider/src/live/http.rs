//! A real, budget-free single-shot HTTP backend used by `ChainReader`.
//!
//! The request URL is held as a [`crate::RedactedUrl`] and only exposed
//! transiently to the transport; it is never logged or formatted.

use std::time::Duration;

use serde_json::{Value, json};
use ureq::Error as UreqError;
use ureq::{Agent, AgentBuilder};

use crate::{HttpBackend, HttpResponse, RedactedUrl, RpcRequest, TransportError};

/// Issues one JSON-RPC POST to the Base HTTP endpoint.
pub struct LiveHttp {
    endpoint: RedactedUrl,
    agent: Agent,
}

impl LiveHttp {
    #[must_use]
    pub fn new(endpoint: RedactedUrl) -> Self {
        let agent = AgentBuilder::new().timeout(Duration::from_secs(30)).build();
        Self { endpoint, agent }
    }
}

impl HttpBackend for LiveHttp {
    fn request(&self, request: &RpcRequest) -> Result<HttpResponse, TransportError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": request.method,
            "params": request.params,
        })
        .to_string();
        let url = self.endpoint.expose().as_str();
        let response = match self
            .agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_bytes(body.as_bytes())
        {
            Ok(response) => response,
            Err(UreqError::Status(code, _)) if code == 429 || code >= 500 => {
                return Err(TransportError::Transient(format!("HTTP status {code}")));
            }
            Err(UreqError::Status(code, _)) => {
                return Err(TransportError::Permanent(format!("HTTP status {code}")));
            }
            Err(UreqError::Transport(error)) => {
                return Err(TransportError::Transient(error.to_string()));
            }
        };
        let text = response
            .into_string()
            .map_err(|error| TransportError::Transient(error.to_string()))?;
        let response_bytes = text.len();
        let value: Value =
            serde_json::from_str(&text).map_err(|_| TransportError::InvalidResponse)?;
        // Audit B9: some gateways emit `"error": null` alongside a result;
        // `get("error")` returns Some(&Null) and the request was previously
        // misclassified Permanent with the baffling message
        // "JSON-RPC error: null".
        if let Some(error) = value.get("error").filter(|e| !e.is_null()) {
            if is_transient_json_rpc_error(error) {
                return Err(TransportError::Transient(format!(
                    "JSON-RPC error: {error}"
                )));
            }
            return Err(TransportError::Permanent(format!(
                "JSON-RPC error: {error}"
            )));
        }
        let result = value
            .get("result")
            .cloned()
            .ok_or(TransportError::InvalidResponse)?;
        Ok(HttpResponse {
            result,
            response_bytes,
        })
    }
}

/// True when a JSON-RPC `error` object indicates a transient upstream
/// condition that should be retried (a public gateway proxying to a busy,
/// timed-out, or unreachable internal node), not a terminal application error.
fn is_transient_json_rpc_error(error: &Value) -> bool {
    // Audit B8: classify on the error CODE first — provider throttling is
    // delivered as -32005 (or a 429-mapped code) with message text that the
    // old substring list never matched, so pure rate-limiting was classified
    // Permanent and aborted runs. Then fall back to message patterns
    // covering both Alchemy and public-gateway phrasing.
    const TRANSIENT_PATTERNS: [&str; 15] = [
        "context deadline exceeded",
        "timeout",
        "timed out",
        "overloaded",
        "too many requests",
        "connection refused",
        "connection reset",
        "dial tcp",
        "eof",
        // Audit B8 additions: provider throttle + gateway phrasing.
        "capacity",
        "rate limit",
        "limit exceeded",
        "try again",
        "temporarily",
        "unavailable",
    ];
    let code = error.get("code").and_then(Value::as_i64);
    if code == Some(-32005) || code == Some(429) {
        return true;
    }
    let message = error
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    TRANSIENT_PATTERNS
        .iter()
        .any(|pattern| message.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::is_transient_json_rpc_error;
    use serde_json::json;

    #[test]
    fn provider_throttle_codes_and_messages_are_transient() {
        // Audit B8: Alchemy's compute-unit throttle arrives as -32005 with
        // message text the old substring list never matched — it was
        // classified Permanent and aborted runs on pure throttling.
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32005,
            "message": "Your app has exceeded its compute units per second capacity."
        })));
        assert!(is_transient_json_rpc_error(&json!({
            "code": 429,
            "message": "rate limit exceeded"
        })));
        // Public-gateway phrasing.
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "service temporarily unavailable"
        })));
    }

    #[test]
    fn timeout_json_rpc_error_is_transient() {
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "Post \"http://10.31.61.37:8547/rpc\": context deadline exceeded"
        })));
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "request timed out"
        })));
    }

    #[test]
    fn unreachable_upstream_json_rpc_error_is_transient() {
        // Regression: the public RHC gateway surfaces an unreachable internal
        // node as a wrapped Go dial error, which canary5 took as fatal
        // (classified Permanent) and aborted the 24h window.
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "Post \"http://10.31.14.59:8547/rpc\": dial tcp 10.31.14.59:8547: connect: connection refused"
        })));
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "Post \"http://10.31.14.59:8547/rpc\": read: connection reset by peer"
        })));
        assert!(is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "Post \"http://10.31.14.59:8547/rpc\": unexpected EOF"
        })));
    }

    #[test]
    fn semantic_json_rpc_errors_are_permanent() {
        assert!(!is_transient_json_rpc_error(&json!({
            "code": -32601,
            "message": "method not found"
        })));
        assert!(!is_transient_json_rpc_error(&json!({
            "code": -32000,
            "message": "missing trie node 0x1234"
        })));
    }
}
