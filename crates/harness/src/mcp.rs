//! The MCP envelope, built once so no row assembles its own.
//!
//! Revision **2026-07-28**. There is no `initialize` and no session: every POST
//! is self-contained. Two things are mandatory on every request and a row that
//! omits either never reaches the contract it claims to test:
//!
//! 1. `params._meta["io.modelcontextprotocol/protocolVersion"]` and
//!    `params._meta["io.modelcontextprotocol/clientCapabilities"]`. Absence is
//!    `-32602` and HTTP 400, raised by `Request::validate` **before dispatch**.
//! 2. The `MCP-Protocol-Version` HEADER. Measured against the live edge on
//!    2026-09-05: a POST without it is answered
//!    `{"error":{"code":-32602,"message":"the MCP-Protocol-Version header is
//!    required on every POST"}}`. It is REQUIRED, not merely cross-checked when
//!    present — `cross_check_headers` takes the header with `ok_or_else`, while
//!    `Mcp-Method` and `Mcp-Name` are compared only `if let Some(..)`.
//!
//! The consequence is about what a row MEASURES, not about whether it is green.
//! C-04 sends a junk bearer token and asserts 401; without the envelope the
//! validator answers 400 before the credential is looked at, and the row would
//! be measuring the validator while reporting on authentication.

use anyhow::Result;
use serde_json::{json, Value};

use crate::capture::Captured;
use crate::client::Edge;
use crate::reference::Reference;

pub const DISCOVER: &str = "server/discover";
pub const TOOLS_LIST: &str = "tools/list";
pub const TOOLS_CALL: &str = "tools/call";

/// `_meta`, whose keys are reverse-DNS namespaced and whose exact strings matter.
///
/// A near-miss parses as a missing required field, so the failure is loud rather
/// than silent — but it is still a failure of this suite rather than of the
/// system, which is why the strings live in one place.
fn meta(reference: &Reference) -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": reference.mcp.protocol_version,
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// Build a JSON-RPC request with the envelope already correct.
pub fn request(reference: &Reference, method: &str, mut params: Value) -> Value {
    let m = params
        .as_object_mut()
        .expect("MCP params are always an object");
    m.insert("_meta".into(), meta(reference));
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": Value::Object(m.clone()) })
}

/// Who is calling, as headers.
///
/// `X-Yadgar-User` is deliberately NOT settable here. It is a caller-written
/// identity header, and C-05 (stage 2) exists to prove the gateway ignores it —
/// that row sets it explicitly and by hand, so that setting it is visible in the
/// one place it is meant to happen.
#[derive(Default, Clone)]
pub struct Caller {
    pub token: Option<String>,
    pub project: Option<String>,
    pub instance: Option<String>,
}

impl Caller {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn bearer(token: impl Into<String>, project: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            project: Some(project.into()),
            instance: None,
        }
    }

    fn headers(&self, reference: &Reference) -> Vec<(&'static str, String)> {
        let mut h = vec![(
            "mcp-protocol-version",
            reference.mcp.protocol_version.clone(),
        )];
        if let Some(t) = &self.token {
            h.push(("authorization", format!("Bearer {t}")));
        }
        if let Some(p) = &self.project {
            h.push(("x-yadgar-project", p.clone()));
        }
        if let Some(i) = &self.instance {
            h.push(("x-yadgar-instance", i.clone()));
        }
        h
    }
}

/// Send one MCP request and capture the answer.
pub async fn post(
    edge: &Edge,
    reference: &Reference,
    caller: &Caller,
    method: &str,
    params: Value,
) -> Result<Captured> {
    let body = serde_json::to_vec(&request(reference, method, params))?;
    let headers: Vec<(&str, String)> = caller.headers(reference);
    edge.post("/", &headers, body).await
}

/// `tools/call`, the only method that authenticates.
pub async fn tools_call(
    edge: &Edge,
    reference: &Reference,
    caller: &Caller,
    name: &str,
    arguments: Value,
) -> Result<Captured> {
    post(
        edge,
        reference,
        caller,
        TOOLS_CALL,
        json!({ "name": name, "arguments": arguments }),
    )
    .await
}

/// The `structuredContent` of a successful `tools/call`, or an explanation.
///
/// A TOOL-level failure is a SUCCESSFUL JSON-RPC result carrying
/// `isError: true`, not a JSON-RPC error — the gateway is explicit about the
/// distinction, and confusing the two is how a row reads a refusal as a
/// transport fault. This returns `Err` for both, with the text, and the caller
/// decides which it expected.
pub fn structured(capture: &Captured) -> Result<Value> {
    let v = capture.json()?;
    if let Some(err) = v.get("error") {
        anyhow::bail!("JSON-RPC error rather than a result: {err}");
    }
    let result = v
        .get("result")
        .ok_or_else(|| anyhow::anyhow!("no `result` in {}", capture.body_str()))?;
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        anyhow::bail!("tool-level failure: {}", capture.body_str());
    }
    result
        .get("structuredContent")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no `structuredContent` in {}", capture.body_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> Reference {
        Reference::load().expect("reference.toml parses")
    }

    /// The envelope is the thing every row depends on, so it is asserted rather
    /// than assumed. Both `_meta` keys, exact strings.
    #[test]
    fn every_request_carries_the_two_required_meta_keys() {
        let r = reference();
        let req = request(&r, TOOLS_LIST, json!({}));
        let meta = &req["params"]["_meta"];
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            json!(r.mcp.protocol_version)
        );
        assert!(
            meta.get("io.modelcontextprotocol/clientCapabilities")
                .is_some(),
            "absence is the error; an empty object is a valid value meaning `no capabilities`"
        );
    }

    /// The header is required on every POST, so it is on every caller shape —
    /// including the anonymous one, which is what `server/discover` and
    /// `tools/list` use.
    #[test]
    fn the_protocol_version_header_is_sent_even_anonymously() {
        let r = reference();
        let h = Caller::anonymous().headers(&r);
        assert!(h
            .iter()
            .any(|(k, v)| *k == "mcp-protocol-version" && *v == r.mcp.protocol_version));
        assert!(
            !h.iter().any(|(k, _)| *k == "authorization"),
            "server/discover and tools/list take no credential"
        );
    }

    /// A caller-written identity header must never be sent by accident.
    #[test]
    fn no_caller_shape_sends_x_yadgar_user() {
        let r = reference();
        let h = Caller::bearer("t", "estate/local").headers(&r);
        assert!(!h.iter().any(|(k, _)| *k == "x-yadgar-user"));
    }
}
