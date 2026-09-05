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
    use rand::RngCore;
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_junk_bearer_is_64_bytes_and_never_repeats() {
        let a = junk_bearer();
        let b = junk_bearer();
        assert_eq!(a.len(), 128, "64 bytes, hex-encoded");
        assert_ne!(a, b);
    }
}
