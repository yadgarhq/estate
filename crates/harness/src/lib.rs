//! The client every behavioural contract is exercised through.
//!
//! ADR-0562: a contract is exercised **through the front door, over the public
//! edge, as a real client does** — DNS, the name-constrained root, and the
//! published API. Nothing in this crate can reach a service directly, and that
//! is deliberate rather than incidental: there is no gRPC client here, no kube
//! client, and no Prometheus client. Those belong to `estate-annex`, which is
//! stage 3, runs on a different runner, and carries a different network policy.
//!
//! Three properties this crate exists to give every row for free.
//!
//! **One trust path.** [`client::Edge::trusting_committed_root`] builds a client
//! whose root store holds `ca/root.pem` and nothing else. A row cannot
//! accidentally validate against the public web PKI, and it cannot accidentally
//! skip validation — there is no constructor that does either. The one client
//! that trusts the public web PKI, [`client::Edge::trusting_public_web_pki`],
//! exists for C-14's negative half and is named so that reading a row makes it
//! obvious which one it used.
//!
//! **Byte-level capture.** [`capture::Captured`] holds the status, the header
//! names and values, and the body as bytes. [`capture::pair_equal`] compares two
//! captures for byte-identity. This is the ADR-0521 method and it is the whole
//! reason the type exists: a test that asserts only "a refusal happened" passes
//! against the version that leaks which refusal it was. The rows that matter
//! compare two captured responses, never two independent status assertions.
//!
//! **An MCP envelope that reaches the contract.** Every request this server
//! accepts must carry `params._meta` with the protocol version and
//! `clientCapabilities`, AND the `MCP-Protocol-Version` header — the header is
//! required on every POST, not merely cross-checked when present (measured
//! 2026-09-05; `gateway/src/mcp.rs:cross_check_headers`). A request missing
//! either is refused 400 at validation, **before dispatch**. That matters for
//! what a row measures rather than for whether it passes: C-04 sends a junk
//! bearer token and asserts 401, and a C-04 that failed validation would be
//! answered 400 by the validator without the credential ever being looked at —
//! a row that measures the envelope and reports on authentication. So the
//! envelope is built in one place, here, and no row assembles its own.

pub mod auth;
pub mod capture;
pub mod client;
pub mod mcp;
pub mod reference;
pub mod run;

pub use capture::{pair_equal, Captured};
pub use client::Edge;
pub use reference::Reference;
