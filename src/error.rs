//! Error types for canonical JSON operations.

use crate::MAX_NESTING_DEPTH;

/// Error type for canonical JSON operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum JcsError {
    /// JSON serialization or deserialization failed.
    Json(serde_json::Error),
    /// A JSON string violated I-JSON constraints.
    InvalidString(String),
    /// A JSON number violated JCS / I-JSON constraints.
    InvalidNumber(String),
    /// The input exceeded [`MAX_NESTING_DEPTH`].
    NestingDepthExceeded,
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "JCS JSON processing failed: {e}"),
            Self::InvalidString(msg) => write!(f, "JCS string validation failed: {msg}"),
            Self::InvalidNumber(msg) => write!(f, "JCS number validation failed: {msg}"),
            Self::NestingDepthExceeded => write!(
                f,
                "JCS nesting depth exceeded maximum of {MAX_NESTING_DEPTH}"
            ),
        }
    }
}

impl std::error::Error for JcsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::InvalidString(_) | Self::InvalidNumber(_) | Self::NestingDepthExceeded => None,
        }
    }
}

impl From<serde_json::Error> for JcsError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Stable downstream projection of [`JcsError`].
///
/// Lets consumers map to their own error type without matching on
/// `JcsError` directly. Intentionally exhaustive: any future `JcsError`
/// variant collapses into [`JcsErrorInfo::Validation`] via
/// [`std::fmt::Display`], so adding variants to `JcsError` cannot break
/// downstream matches on `JcsErrorInfo`.
#[derive(Debug)]
pub enum JcsErrorInfo {
    /// Structured `serde_json` error preserved as-is.
    Json(serde_json::Error),
    /// Any non-`Json` failure rendered as a message.
    Validation(String),
}

impl JcsError {
    /// Project into the stable [`JcsErrorInfo`] view.
    #[must_use]
    pub fn into_info(self) -> JcsErrorInfo {
        match self {
            Self::Json(err) => JcsErrorInfo::Json(err),
            Self::InvalidString(msg) | Self::InvalidNumber(msg) => JcsErrorInfo::Validation(msg),
            other => JcsErrorInfo::Validation(other.to_string()),
        }
    }
}
