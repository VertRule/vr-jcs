//! ADR-003 Ratification Criterion C4 — `JcsError::into_info()` projects
//! every variant correctly: `Json` → `JcsErrorInfo::Json(_)`; every other
//! variant → `JcsErrorInfo::Validation(_)` with a non-empty message.
//!
//! Six tests, one per variant. Splitting per variant keeps failure
//! attribution clear and exercises the projection match arms
//! independently.

use vr_jcs::{JcsError, JcsErrorInfo};

#[test]
fn json_variant_projects_to_json_info() {
    let result: Result<serde_json::Value, _> = serde_json::from_str("not json");
    assert!(result.is_err());
    if let Err(serde_err) = result {
        let info = JcsError::from(serde_err).into_info();
        assert!(
            matches!(info, JcsErrorInfo::Json(_)),
            "Json variant must project to JcsErrorInfo::Json",
        );
    }
}

#[test]
fn duplicate_key_projects_to_validation_with_message() {
    let info = JcsError::DuplicateKey("duplicate property name `x`".to_string()).into_info();
    assert!(matches!(&info, JcsErrorInfo::Validation(_)));
    if let JcsErrorInfo::Validation(msg) = info {
        assert!(!msg.is_empty(), "DuplicateKey projection must carry a non-empty message");
    }
}

#[test]
fn invalid_string_projects_to_validation_with_message() {
    let info = JcsError::InvalidString("forbidden noncharacter U+FDD0".to_string()).into_info();
    assert!(matches!(&info, JcsErrorInfo::Validation(_)));
    if let JcsErrorInfo::Validation(msg) = info {
        assert!(!msg.is_empty(), "InvalidString projection must carry a non-empty message");
    }
}

#[test]
fn invalid_number_projects_to_validation_with_message() {
    let info = JcsError::InvalidNumber("non-exact integer 2^53+1".to_string()).into_info();
    assert!(matches!(&info, JcsErrorInfo::Validation(_)));
    if let JcsErrorInfo::Validation(msg) = info {
        assert!(!msg.is_empty(), "InvalidNumber projection must carry a non-empty message");
    }
}

#[test]
fn nesting_depth_exceeded_projects_to_validation_with_message() {
    let info = JcsError::NestingDepthExceeded.into_info();
    assert!(matches!(&info, JcsErrorInfo::Validation(_)));
    if let JcsErrorInfo::Validation(msg) = info {
        // The unit variant has no payload; the projection uses Display.
        assert!(
            !msg.is_empty(),
            "NestingDepthExceeded projection must carry a non-empty Display-derived message",
        );
    }
}

#[test]
fn unsupported_algorithm_projects_to_validation_with_message() {
    let info = JcsError::UnsupportedAlgorithm("sha256 not wired".to_string()).into_info();
    assert!(matches!(&info, JcsErrorInfo::Validation(_)));
    if let JcsErrorInfo::Validation(msg) = info {
        assert!(!msg.is_empty(), "UnsupportedAlgorithm projection must carry a non-empty message");
    }
}
