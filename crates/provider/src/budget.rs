use std::sync::{Arc, Mutex};

use thiserror::Error;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageSnapshot {
    pub request_cu: u64,
    pub http_response_bytes: u64,
    pub websocket_delivered_bytes: u64,
    pub websocket_accounted_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BudgetExceeded {
    #[error("request-CU ceiling {ceiling} would be reached")]
    RequestCu { ceiling: u64 },
    #[error("WebSocket-byte ceiling {ceiling} would be reached")]
    WebSocketBytes { ceiling: u64 },
    #[error("provider usage accounting overflow")]
    Overflow,
}

#[derive(Debug, Clone)]
pub struct ProviderBudget {
    request_cu_ceiling: u64,
    websocket_bytes_ceiling: u64,
    usage: Arc<Mutex<UsageSnapshot>>,
}

impl ProviderBudget {
    #[must_use]
    pub fn new(request_cu_ceiling: u64, websocket_bytes_ceiling: u64) -> Self {
        Self {
            request_cu_ceiling,
            websocket_bytes_ceiling,
            usage: Arc::new(Mutex::new(UsageSnapshot::default())),
        }
    }

    /// Charges one successful or attempted HTTP request.
    ///
    /// # Errors
    ///
    /// Returns an error before accounting reaches the configured request-CU
    /// ceiling or if byte accounting overflows.
    pub fn charge_http(&self, method: &str, response_bytes: usize) -> Result<(), BudgetExceeded> {
        let cost = method_cost(method);
        let response_bytes = u64::try_from(response_bytes).map_err(|_| BudgetExceeded::Overflow)?;
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_cu = usage
            .request_cu
            .checked_add(cost)
            .ok_or(BudgetExceeded::Overflow)?;
        if next_cu >= self.request_cu_ceiling {
            return Err(BudgetExceeded::RequestCu {
                ceiling: self.request_cu_ceiling,
            });
        }
        usage.request_cu = next_cu;
        usage.http_response_bytes = usage
            .http_response_bytes
            .checked_add(response_bytes)
            .ok_or(BudgetExceeded::Overflow)?;
        Ok(())
    }

    /// Charges one delivered WebSocket message plus 20% protocol overhead.
    ///
    /// # Errors
    ///
    /// Returns an error before accounting reaches the configured WebSocket-byte
    /// ceiling or if byte accounting overflows.
    pub fn charge_ws_message(&self, response_bytes: usize) -> Result<(), BudgetExceeded> {
        let delivered = u64::try_from(response_bytes).map_err(|_| BudgetExceeded::Overflow)?;
        let accounted = delivered
            .checked_mul(6)
            .and_then(|bytes| bytes.checked_add(4))
            .map(|bytes| bytes / 5)
            .ok_or(BudgetExceeded::Overflow)?;
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = usage
            .websocket_accounted_bytes
            .checked_add(accounted)
            .ok_or(BudgetExceeded::Overflow)?;
        if next >= self.websocket_bytes_ceiling {
            return Err(BudgetExceeded::WebSocketBytes {
                ceiling: self.websocket_bytes_ceiling,
            });
        }
        usage.websocket_delivered_bytes = usage
            .websocket_delivered_bytes
            .checked_add(delivered)
            .ok_or(BudgetExceeded::Overflow)?;
        usage.websocket_accounted_bytes = next;
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> UsageSnapshot {
        *self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn charge_http_response(&self, response_bytes: usize) -> Result<(), BudgetExceeded> {
        let response_bytes = u64::try_from(response_bytes).map_err(|_| BudgetExceeded::Overflow)?;
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        usage.http_response_bytes = usage
            .http_response_bytes
            .checked_add(response_bytes)
            .ok_or(BudgetExceeded::Overflow)?;
        Ok(())
    }
}

fn method_cost(method: &str) -> u64 {
    match method {
        "eth_call" => 26,
        "eth_getLogs" => 60,
        _ => 10,
    }
}
