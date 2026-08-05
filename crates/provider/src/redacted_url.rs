use std::{fmt, str::FromStr};

use thiserror::Error;
use url::Url;

#[derive(Clone)]
pub struct RedactedUrl(Url);

impl RedactedUrl {
    #[must_use]
    pub fn expose(&self) -> &Url {
        &self.0
    }
}

impl FromStr for RedactedUrl {
    type Err = RedactedUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(value).map_err(RedactedUrlError::Invalid)?;
        match url.scheme() {
            "http" | "https" | "ws" | "wss" => Ok(Self(url)),
            _ => Err(RedactedUrlError::UnsupportedScheme),
        }
    }
}

impl fmt::Debug for RedactedUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedUrl([REDACTED])")
    }
}

impl fmt::Display for RedactedUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Error)]
pub enum RedactedUrlError {
    #[error("invalid provider URL")]
    Invalid(#[source] url::ParseError),
    #[error("unsupported provider URL scheme")]
    UnsupportedScheme,
}
