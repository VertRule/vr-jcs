//! Error types for canonical JSON operations.

use crate::MAX_NESTING_DEPTH;

/// Error type for canonical JSON operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum JcsError {
    /// JSON serialization or deserialization failed.
    Json(serde_json::Error),
    /// A strict-path admission detected a duplicate object property
    /// name. The string carries the underlying `serde_json` error
    /// rendering for diagnostic purposes. Code: `"duplicate-key"`.
    DuplicateKey(String),
    /// A JSON string violated I-JSON constraints.
    InvalidString(String),
    /// A JSON number violated JCS / I-JSON constraints.
    InvalidNumber(String),
    /// The input exceeded [`MAX_NESTING_DEPTH`].
    NestingDepthExceeded,
    /// A digest algorithm variant was requested but is not wired in this
    /// build. Carried so callers can distinguish "algorithm is declared but
    /// unimplemented here" from "algorithm is wrong".
    UnsupportedAlgorithm(String),
}

impl JcsError {
    /// Stable kebab-case identifier for this error class. Code values
    /// are part of the public contract (ADR-003 § Decision item 4) —
    /// once published, a code is never renamed or removed.
    ///
    /// | Variant | Code |
    /// |---|---|
    /// | [`Self::Json`] | `"json-parse"` |
    /// | [`Self::DuplicateKey`] | `"duplicate-key"` |
    /// | [`Self::InvalidString`] | `"i-json-string"` |
    /// | [`Self::InvalidNumber`] | `"i-json-number"` |
    /// | [`Self::NestingDepthExceeded`] | `"nesting-depth"` |
    /// | [`Self::UnsupportedAlgorithm`] | `"unsupported-algorithm"` |
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "json-parse",
            Self::DuplicateKey(_) => "duplicate-key",
            Self::InvalidString(_) => "i-json-string",
            Self::InvalidNumber(_) => "i-json-number",
            Self::NestingDepthExceeded => "nesting-depth",
            Self::UnsupportedAlgorithm(_) => "unsupported-algorithm",
        }
    }
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "JCS JSON processing failed: {e}"),
            Self::DuplicateKey(msg) => write!(f, "JCS duplicate property name: {msg}"),
            Self::InvalidString(msg) => write!(f, "JCS string validation failed: {msg}"),
            Self::InvalidNumber(msg) => write!(f, "JCS number validation failed: {msg}"),
            Self::NestingDepthExceeded => write!(
                f,
                "JCS nesting depth exceeded maximum of {MAX_NESTING_DEPTH}"
            ),
            Self::UnsupportedAlgorithm(name) => {
                write!(f, "digest algorithm not wired in this build: {name}")
            }
        }
    }
}

impl std::error::Error for JcsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::DuplicateKey(_)
            | Self::InvalidString(_)
            | Self::InvalidNumber(_)
            | Self::NestingDepthExceeded
            | Self::UnsupportedAlgorithm(_) => None,
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
            Self::DuplicateKey(msg)
            | Self::InvalidString(msg)
            | Self::InvalidNumber(msg)
            | Self::UnsupportedAlgorithm(msg) => JcsErrorInfo::Validation(msg),
            other => JcsErrorInfo::Validation(other.to_string()),
        }
    }
}
