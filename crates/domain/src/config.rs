use std::{env, fmt, fs, path::Path, path::PathBuf};

use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::Chain;

/// The role of an RPC URL, which selects the accepted URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRole {
    Http,
    WebSocket,
}

#[derive(Clone)]
pub struct RpcUrl(Url);

impl RpcUrl {
    fn parse(
        variable: &'static str,
        role: UrlRole,
        value: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let value = value.ok_or(ConfigError::MissingEnvironment(variable))?;
        let url =
            Url::parse(value).map_err(|source| ConfigError::InvalidUrl { variable, source })?;
        let scheme_ok = match role {
            UrlRole::Http => matches!(url.scheme(), "http" | "https"),
            UrlRole::WebSocket => matches!(url.scheme(), "ws" | "wss"),
        };
        if scheme_ok {
            Ok(Self(url))
        } else {
            Err(ConfigError::InvalidUrlScheme(variable))
        }
    }

    #[must_use]
    pub fn expose(&self) -> &Url {
        &self.0
    }
}

impl fmt::Debug for RpcUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcUrl([REDACTED])")
    }
}

impl fmt::Display for RpcUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowConfig {
    pub chain_id: u64,
    pub max_hops: u8,
    pub pool_cap: u32,
    pub stale_timeout_seconds: u64,
    pub recovery_gap_blocks: u64,
    pub dirty_lag_milliseconds: u64,
    pub request_cu_ceiling: u64,
    pub websocket_bytes_ceiling: u64,
    pub database_limit_bytes: u64,
    /// Path to the offline catalog (pools CSV) used by offline commands.
    pub manifest_path: Option<PathBuf>,
    #[serde(skip, default)]
    pub chain: Option<Chain>,
    #[serde(skip)]
    pub http_rpc_url: Option<RpcUrl>,
    #[serde(skip)]
    pub websocket_rpc_url: Option<RpcUrl>,
}

impl ShadowConfig {
    /// Loads non-secret settings from TOML and RPC URLs from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed, required RPC
    /// environment variables are absent or invalid, or validation fails.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let input = fs::read_to_string(path).map_err(ConfigError::Read)?;
        let config = toml::from_str::<Self>(&input).map_err(ConfigError::Parse)?;
        let chain = config.resolve_chain()?;
        let http = env::var(chain.http_env_var()).ok();
        let websocket = env::var(chain.ws_env_var()).ok();
        let mut config = config;
        config.chain = Some(chain);
        config.http_rpc_url = Some(RpcUrl::parse(
            chain.http_env_var(),
            UrlRole::Http,
            http.as_deref(),
        )?);
        config.websocket_rpc_url = Some(RpcUrl::parse(
            chain.ws_env_var(),
            UrlRole::WebSocket,
            websocket.as_deref(),
        )?);
        Ok(config)
    }

    /// Reads only the offline catalog path from a TOML file. Does not require
    /// the RPC environment, so it is safe for fully offline commands.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or is not valid TOML.
    pub fn manifest_path_from(path: &Path) -> Result<Option<PathBuf>, ConfigError> {
        let input = fs::read_to_string(path).map_err(ConfigError::Read)?;
        toml::from_str::<Self>(&input)
            .map(|config| config.manifest_path)
            .map_err(ConfigError::Parse)
    }

    #[cfg(test)]
    fn from_toml_and_urls(
        input: &str,
        http: Option<&str>,
        websocket: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        let chain = config.resolve_chain()?;
        config.chain = Some(chain);
        config.http_rpc_url = Some(RpcUrl::parse(chain.http_env_var(), UrlRole::Http, http)?);
        config.websocket_rpc_url = Some(RpcUrl::parse(
            chain.ws_env_var(),
            UrlRole::WebSocket,
            websocket,
        )?);
        Ok(config)
    }

    fn resolve_chain(&self) -> Result<Chain, ConfigError> {
        Chain::from_id(self.chain_id)
            .ok_or(ConfigError::InvalidChainId(self.chain_id))
            .and_then(|chain| {
                if !(2..=4).contains(&self.max_hops) {
                    return Err(ConfigError::InvalidMaxHops(self.max_hops));
                }
                Ok(chain)
            })
    }
}

impl fmt::Display for ShadowConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ShadowConfig(chain_id={}, max_hops={}, pool_cap={}, http_rpc_url=[REDACTED], websocket_rpc_url=[REDACTED])",
            self.chain_id, self.max_hops, self.pool_cap
        )
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to parse configuration: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("missing required environment variable {0}")]
    MissingEnvironment(&'static str),
    #[error("chain ID {0} is unsupported; supported: 8453 (base), 4663 (robinhood)")]
    InvalidChainId(u64),
    #[error("max_hops must be in 2..=4, got {0}")]
    InvalidMaxHops(u8),
    #[error("{variable} is not a valid URL: {source}")]
    InvalidUrl {
        variable: &'static str,
        #[source]
        source: url::ParseError,
    },
    #[error("{0} has an invalid URL scheme")]
    InvalidUrlScheme(&'static str),
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, ShadowConfig};

    const VALID_TOML: &str = r"
chain_id = 8453
max_hops = 4
pool_cap = 2000
stale_timeout_seconds = 60
recovery_gap_blocks = 1000
dirty_lag_milliseconds = 500
request_cu_ceiling = 24000000
websocket_bytes_ceiling = 5000000000
database_limit_bytes = 10000000000
";

    #[test]
    fn missing_rpc_urls_fail() {
        let error = ShadowConfig::from_toml_and_urls(VALID_TOML, None, None).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::MissingEnvironment("BASE_HTTP_RPC_URL")
        ));

        let error = ShadowConfig::from_toml_and_urls(
            VALID_TOML,
            Some("https://base.example/v2/http-secret"),
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ConfigError::MissingEnvironment("BASE_WS_RPC_URL")
        ));
    }

    #[test]
    fn rejects_non_base_chain_id() {
        let input = VALID_TOML.replace("chain_id = 8453", "chain_id = 1");
        let error = ShadowConfig::from_toml_and_urls(
            &input,
            Some("https://base.example/v2/http-secret"),
            Some("wss://base.example/v2/ws-secret"),
        )
        .unwrap_err();
        assert!(matches!(error, ConfigError::InvalidChainId(1)));
    }

    #[test]
    fn accepts_robinhood_chain_id_with_chain_env_names() {
        let input = VALID_TOML.replace("chain_id = 8453", "chain_id = 4663");
        let config = ShadowConfig::from_toml_and_urls(
            &input,
            Some("https://robinhood.example/v2/http-secret"),
            Some("wss://robinhood.example/v2/ws-secret"),
        )
        .unwrap();
        assert_eq!(config.chain, Some(crate::Chain::Robinhood));
        assert_eq!(config.chain_id, crate::ROBINHOOD_CHAIN_ID);

        let error = ShadowConfig::from_toml_and_urls(&input, None, None).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::MissingEnvironment("ROBINHOOD_HTTP_RPC_URL")
        ));
    }

    #[test]
    fn rejects_max_hops_outside_supported_range() {
        for max_hops in [1, 5] {
            let input = VALID_TOML.replace("max_hops = 4", &format!("max_hops = {max_hops}"));
            let error = ShadowConfig::from_toml_and_urls(
                &input,
                Some("https://base.example/v2/http-secret"),
                Some("wss://base.example/v2/ws-secret"),
            )
            .unwrap_err();
            assert!(matches!(error, ConfigError::InvalidMaxHops(value) if value == max_hops));
        }
    }

    #[test]
    fn debug_and_display_redact_rpc_urls() {
        let http = "https://base.example/v2/http-secret";
        let websocket = "wss://base.example/v2/ws-secret";
        let config =
            ShadowConfig::from_toml_and_urls(VALID_TOML, Some(http), Some(websocket)).unwrap();

        for rendered in [format!("{config:?}"), config.to_string()] {
            assert!(!rendered.contains(http));
            assert!(!rendered.contains(websocket));
            assert!(!rendered.contains("http-secret"));
            assert!(!rendered.contains("ws-secret"));
        }
    }
}
