//! `POST /auth/login` and `POST /auth/enrol` — the two paths on this server that
//! are not MCP, and the only two that take no credential to reach.
//!
//! CREDENTIAL ACQUISITION AND THE FIRST CONTRACT ARE THE SAME CALL. The suite
//! holds no bearer token anywhere: it starts every run with a login, which IS
//! contract C-01. What is stored is a password, in one GitHub environment that
//! only the suite workflows may name.

use anyhow::{Context, Result};
use serde_json::json;

use crate::capture::Captured;
use crate::client::Edge;

/// Attempt a login. Returns the captured response, refusal or not.
///
/// Deliberately does NOT return a token type. C-02 and C-03 are refusals and
/// need every observable byte of them; a helper that returned `Result<Token>`
/// would throw the refusal away and leave those rows unable to compare.
pub async fn login(edge: &Edge, username: &str, password: &str) -> Result<Captured> {
    let body = serde_json::to_vec(&json!({ "username": username, "password": password }))?;
    edge.post("/auth/login", &[], body).await
}

/// Redeem an enrolment secret. Stage 3 (C-08/C-09) is its first caller.
///
/// Present now because the shape belongs beside `login`, and because leaving it
/// out would invite a stage-3 row to build its own request — which is how two
/// callers end up disagreeing about a contract.
pub async fn enrol(edge: &Edge, secret: &str, password: &str) -> Result<Captured> {
    let body = serde_json::to_vec(&json!({ "secret": secret, "password": password }))?;
    edge.post("/auth/enrol", &[], body).await
}

/// The token out of a successful login, and an error naming the body otherwise.
pub fn token_of(capture: &Captured) -> Result<String> {
    let v = capture
        .json()
        .with_context(|| format!("login answered {}: {}", capture.status, capture.body_str()))?;
    v.get("token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no `token` in {}", capture.body_str()))
}

/// A bearer token that is 64 random bytes and belongs to nobody (C-04).
///
/// Random per call rather than a constant: a fixed string would be one somebody
/// could eventually make valid, and a row asserting "this exact string is
/// refused" would then be asserting nothing.
pub fn junk_bearer() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why a login body breaks C-01, or `None` when it is exactly `{token, expires_at}`.
///
/// The key set is EXACT, never "contains token": a third key would be credential
/// material beyond the token. `expires_at` joined the body with ADR-0972 (3). The
/// gateway renders it with `prost_types::Timestamp`'s `Display` (gateway
/// `src/http/auth.rs` `with_expiry`): a JSON string, RFC 3339 in UTC, `Z` suffix,
/// optional fraction of 1-9 digits. Any other type or shape is a contract change.
pub fn login_body_problem(body: &serde_json::Value) -> Option<String> {
    let Some(map) = body.as_object() else {
        return Some(format!("the login body is not a JSON object: {body}"));
    };
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["expires_at", "token"] {
        return Some(format!(
            "the login body's key set is {keys:?}, not exactly [\"expires_at\", \"token\"]. \
             A further key is credential material leaking beside the token."
        ));
    }
    match map["expires_at"].as_str() {
        Some(t) if is_utc_rfc3339(t) => None,
        other => Some(format!(
            "expires_at is {other:?}, not an RFC 3339 UTC string like 2026-10-25T10:25:02.123456Z"
        )),
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z`, with in-range fields.
fn is_utc_rfc3339(t: &str) -> bool {
    let b = t.as_bytes();
    if b.len() < 20 || b[b.len() - 1] != b'Z' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r.clone()].iter().all(u8::is_ascii_digit);
    let num = |r: std::ops::Range<usize>| t[r].parse::<u32>().unwrap_or(u32::MAX);
    let shape = digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    if !shape
        || !(1..=12).contains(&num(5..7))
        || !(1..=31).contains(&num(8..10))
        || num(11..13) > 23
        || num(14..16) > 59
        || num(17..19) > 60
    {
        return false;
    }
    let rest = &b[19..b.len() - 1];
    rest.is_empty()
        || (rest[0] == b'.'
            && (1..=9).contains(&(rest.len() - 1))
            && rest[1..].iter().all(u8::is_ascii_digit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_login_body_of_exactly_token_and_expires_at_passes() {
        for at in [
            "2026-10-25T10:25:02Z",
            "2026-10-25T10:25:02.123456Z",
            "2026-10-25T10:25:02.1Z",
        ] {
            assert_eq!(
                login_body_problem(&json!({"token": "t", "expires_at": at})),
                None,
                "{at}"
            );
        }
    }

    #[test]
    fn the_key_set_stays_exact() {
        let at = "2026-10-25T10:25:02Z";
        assert!(
            login_body_problem(&json!({"token": "t"})).is_some(),
            "expires_at is required"
        );
        assert!(
            login_body_problem(&json!({"expires_at": at})).is_some(),
            "token is required"
        );
        assert!(
            login_body_problem(&json!({"token": "t", "expires_at": at, "username": "u"})).is_some(),
            "a third key"
        );
        assert!(
            login_body_problem(&json!({"token": "t", "expires_at": at, "credential_id": "c"}))
                .is_some()
        );
        assert!(
            login_body_problem(&json!(["token", "expires_at"])).is_some(),
            "not an object"
        );
    }

    #[test]
    fn expires_at_must_be_an_rfc3339_utc_string() {
        for bad in [
            json!(1761387902),
            json!(null),
            json!("tomorrow"),
            json!("2026-10-25 10:25:02Z"),
            json!("2026-10-25T10:25:02+02:00"),
            json!("2026-10-25T10:25:02"),
            json!("2026-13-25T10:25:02Z"),
            json!("2026-10-25T10:25:02.Z"),
            json!("2026-10-25T10:25:02.1234567890Z"),
        ] {
            assert!(
                login_body_problem(&json!({"token": "t", "expires_at": bad})).is_some(),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_junk_bearer_is_64_bytes_and_never_repeats() {
        let a = junk_bearer();
        let b = junk_bearer();
        assert_eq!(a.len(), 128, "64 bytes, hex-encoded");
        assert_ne!(a, b);
    }
}
