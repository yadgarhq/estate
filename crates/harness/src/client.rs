//! The one way this suite reaches the estate.
//!
//! Two constructors, both named for what they trust. There is no third, and in
//! particular there is no constructor that skips validation: the property C-14
//! exists to police is that the edge serves the certificate a real client
//! validates, and a suite able to turn validation off is a suite that will,
//! the first time a certificate is inconvenient.

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::capture::Captured;
use crate::reference::Reference;

/// A client pointed at the edge.
pub struct Edge {
    client: reqwest::Client,
    base: String,
}

/// How long any single request may take.
///
/// Generous rather than tight. `iam` holds every failed login to a response-time
/// floor and pays Argon2id on a username it has never seen, so a bound near the
/// healthy latency would fail rows for being slow rather than for being wrong.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn builder(reference: &Reference) -> Result<reqwest::ClientBuilder> {
    let mut b = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // A redirect this suite followed would be a redirect it stopped
        // observing. Every row asserts on the FIRST answer.
        .redirect(reqwest::redirect::Policy::none())
        // No plaintext, ever. The edge is TLS and a row that silently fell back
        // to `http://` would be validating nothing.
        .https_only(true);

    // Resolution may be redirected; trust never is.
    //
    // IN-CLUSTER NOTHING IS SET HERE. The runner pod resolves the name through a
    // `hostAliases` entry pointing at `yadgar-edge`, a stable Service on a pinned
    // ClusterIP in front of the same Envoy pods. Both are declared in
    // `yadgarhq/deploy` (`infra/estate-front/edge-service.yaml` and
    // `infra/estate-front-runner.yaml`), because applying them is a cluster
    // change and this repository applies nothing.
    //
    // NOT A CoreDNS REWRITE, which is what the design named. Verified 2026-09-05:
    // `kube-system/coredns`'s Corefile carries no `rewrite` line, and none is
    // being added — that ConfigMap is written by kubeadm when kind creates the
    // cluster, so an Argo-managed copy would be two writers of one object
    // (ADR-0480). The consequence worth knowing is that the name resolves in the
    // runner pod and nowhere else in the cluster.
    //
    // From a workstation the name has no DNS record either, so the address is
    // supplied — the client still dials the external NAME, sends it as SNI, and
    // validates the same leaf against the same chain.
    if let Ok(ip) = std::env::var("ESTATE_EDGE_RESOLVE") {
        let addr: std::net::IpAddr = ip
            .parse()
            .with_context(|| format!("ESTATE_EDGE_RESOLVE={ip} is not an IP address"))?;
        b = b.resolve(
            &reference.edge.host,
            std::net::SocketAddr::new(addr, reference.port()),
        );
    }
    Ok(b)
}

impl Edge {
    /// The client every row but C-14's negative half uses.
    ///
    /// Its root store holds `ca/root.pem` and nothing else — `tls_built_in_root_certs(false)`
    /// is what makes that true rather than merely intended. A leaf signed by any
    /// public CA is rejected by this client, which is half of C-14's assertion
    /// and is free for every other row.
    pub fn trusting_committed_root(reference: &Reference) -> Result<Self> {
        let pem = reference.root_pem()?;
        let root = reqwest::Certificate::from_pem(&pem)
            .context("ca/root.pem is not a certificate this client can load")?;
        let client = builder(reference)?
            .tls_built_in_root_certs(false)
            .add_root_certificate(root)
            .build()?;
        Ok(Self {
            client,
            base: reference.base_url(),
        })
    }

    /// C-14's negative half, and nothing else.
    ///
    /// Trusts the Mozilla bundle and NOT the committed root. A handshake that
    /// SUCCEEDS here means something other than our edge — or a publicly-trusted
    /// certificate — is answering on the name, and the suite would then be
    /// validating a path no real client uses.
    pub fn trusting_public_web_pki(reference: &Reference) -> Result<Self> {
        let client = builder(reference)?.tls_built_in_root_certs(true).build()?;
        Ok(Self {
            client,
            base: reference.base_url(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// POST a body and capture everything observable about the answer.
    pub async fn post(
        &self,
        path: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<Captured> {
        self.send(reqwest::Method::POST, path, headers, Some(body))
            .await
    }

    /// Any method, no body. C-12 (stage 2) sends `GET` and `DELETE` here.
    pub async fn request_without_body(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<Captured> {
        self.send(method, path, &[], None).await
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, String)],
        body: Option<Vec<u8>>,
    ) -> Result<Captured> {
        let url = format!("{}{path}", self.base);
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(
                HeaderName::from_bytes(k.as_bytes())?,
                HeaderValue::from_str(v)?,
            );
        }
        let mut req = self.client.request(method, &url).headers(map);
        if let Some(b) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(b);
        }
        let resp = req.send().await.with_context(|| format!("POST {url}"))?;
        capture(resp).await
    }
}

async fn capture(resp: reqwest::Response) -> Result<Captured> {
    let status = resp.status().as_u16();
    let http_version = format!("{:?}", resp.version());
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = resp.bytes().await?.to_vec();
    Ok(Captured {
        status,
        headers,
        body,
        http_version,
    })
}
