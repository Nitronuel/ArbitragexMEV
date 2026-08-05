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
        if let Some(error) = value.get("error") {
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
