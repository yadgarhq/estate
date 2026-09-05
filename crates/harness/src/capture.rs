//! A captured response, and the pair-equality assertion built on it.
//!
//! ADR-0521's method, in a type. The finding that ADR was written from is that a
//! design answering several internal outcomes with one refusal must equalise
//! **every channel a caller can observe** — status code, body, headers, and
//! time — and that a control equalising one dimension equalises no other. A test
//! that asserts "both were refused" passes against the version where one refusal
//! is `INVALID_ARGUMENT` and the other is `UNAUTHENTICATED`, which is exactly
//! the oracle that shipped.
//!
//! So the rows that police an oracle capture two responses and compare them
//! byte for byte. They never assert a status twice.

use std::collections::BTreeSet;

use anyhow::{bail, Result};

/// Everything a caller can observe about one HTTP response, kept verbatim.
#[derive(Debug, Clone)]
pub struct Captured {
    pub status: u16,
    /// Lowercased names with their values.
    ///
    /// **THE ORDER IS NOT THE ORDER RECEIVED, AND NOTHING HERE MAY DEPEND ON
    /// IT.** These come from `reqwest`'s `HeaderMap::iter()`, which yields the
    /// internal hash-table order rather than the wire order; the wire order is
    /// discarded before this type ever sees the response and cannot be
    /// recovered. Kept as a `Vec` rather than a set because a REPEATED header is
    /// observable and a `Vec` keeps the repetition — but [`pair_equal`] compares
    /// these as a MULTISET for exactly this reason.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The negotiated HTTP version. Not compared by [`pair_equal`]; recorded
    /// because C-16 (stage 2) needs `h2` and a row asserting it should read the
    /// value rather than assume it.
    pub http_version: String,
}

/// Headers excluded from pair-equality.
///
/// `date` only, and the list is deliberately this short. Every other header is
/// part of what a caller sees, so excluding one would be excluding evidence.
/// `date` changes between two requests for reasons that have nothing to do with
/// the responses differing.
const VOLATILE: &[&str] = &["date"];

impl Captured {
    /// The set of header names, lowercased.
    ///
    /// C-02 compares this against the declared infrastructure allowlist as a
    /// **subset** test in one direction and a closed set in the other: a name
    /// outside the allowlist fails the row.
    pub fn header_names(&self) -> BTreeSet<String> {
        self.headers.iter().map(|(k, _)| k.clone()).collect()
    }

    /// Whether a header is present at all.
    ///
    /// C-02 asserts `www-authenticate` is absent. Absence is the assertion: a
    /// challenge header on a refusal tells a caller which side of verification
    /// failed, which is what ADR-0507's two-status collapse exists to hide.
    pub fn has_header(&self, name: &str) -> bool {
        let want = name.to_ascii_lowercase();
        self.headers.iter().any(|(k, _)| *k == want)
    }

    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    /// The header pairs that participate in pair-equality, SORTED.
    ///
    /// Sorted because the order this type holds is a hash-table artifact rather
    /// than anything a caller observed — see the `headers` field. An
    /// order-sensitive comparison would therefore go red on a difference that
    /// exists only inside `HeaderMap`, and a false red on an oracle row is worse
    /// than no row: it is the red people learn to ignore. Sorting compares
    /// exactly what this type can honestly claim to have seen — WHICH headers,
    /// with WHICH values, HOW MANY TIMES — and duplicates survive the sort, so a
    /// repeated header still differs from a single one.
    fn stable_headers(&self) -> Vec<(String, String)> {
        let mut kept: Vec<(String, String)> = self
            .headers
            .iter()
            .filter(|(k, _)| !VOLATILE.contains(&k.as_str()))
            .cloned()
            .collect();
        kept.sort();
        kept
    }
}

/// Assert two responses are indistinguishable to a caller.
///
/// Status, the body byte for byte, and every header except `date` — the headers
/// as a MULTISET, not a sequence, because their order here is `HeaderMap`'s
/// internal one rather than the wire's. See [`Captured::stable_headers`].
///
/// The error names WHICH channel differed, because that is the whole diagnostic
/// value: a row going red with "they differ" sends the reader back to the wire,
/// and a row going red with "status 400 vs 401" names the oracle.
pub fn pair_equal(a: &Captured, b: &Captured, what: &str) -> Result<()> {
    if a.status != b.status {
        bail!(
            "{what}: the two responses are distinguishable BY STATUS — {} vs {}. \
             A caller learns which case it hit from the status code alone.",
            a.status,
            b.status
        );
    }
    let (ah, bh) = (a.stable_headers(), b.stable_headers());
    if ah != bh {
        bail!(
            "{what}: the two responses are distinguishable BY HEADERS — {ah:?} vs {bh:?}. \
             `date` is already excluded, so this is a real difference."
        );
    }
    if a.body != b.body {
        bail!(
            "{what}: the two responses are distinguishable BY BODY — {:?} vs {:?}.",
            a.body_str(),
            b.body_str()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(status: u16, headers: &[(&str, &str)], body: &str) -> Captured {
        Captured {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
            http_version: "HTTP/2.0".into(),
        }
    }

    /// The assertion must survive the ONE difference every pair really has.
    #[test]
    fn a_differing_date_is_not_a_difference() {
        let a = cap(401, &[("date", "Sat, 05 Sep 2026 06:41:32 GMT")], "no");
        let b = cap(401, &[("date", "Sat, 05 Sep 2026 06:41:33 GMT")], "no");
        pair_equal(&a, &b, "test").expect("only the date differs");
    }

    /// The exact defect ADR-0521 was written from: one refusal, two codes.
    #[test]
    fn a_differing_status_is_caught_and_named() {
        let a = cap(400, &[], "refused");
        let b = cap(401, &[], "refused");
        let e = pair_equal(&a, &b, "C-XX").expect_err("statuses differ");
        assert!(e.to_string().contains("BY STATUS"), "{e}");
    }

    /// Same status, same headers, different words is still an oracle.
    #[test]
    fn a_differing_body_is_caught() {
        let a = cap(401, &[], "already redeemed");
        let b = cap(401, &[], "no such secret");
        let e = pair_equal(&a, &b, "C-XX").expect_err("bodies differ");
        assert!(e.to_string().contains("BY BODY"), "{e}");
    }

    /// A header nobody expected is evidence, so it must not be filtered away.
    #[test]
    fn a_differing_header_is_caught() {
        let a = cap(401, &[("www-authenticate", "Basic")], "no");
        let b = cap(401, &[], "no");
        let e = pair_equal(&a, &b, "C-XX").expect_err("headers differ");
        assert!(e.to_string().contains("BY HEADERS"), "{e}");
    }

    /// The order `HeaderMap::iter()` happens to yield is not evidence, so two
    /// responses carrying the SAME headers must compare equal whatever order
    /// this type received them in. Without this, an oracle row could go red on a
    /// hash-table artifact — a false red on the one kind of row where a false
    /// red is most expensive.
    #[test]
    fn header_order_is_not_a_difference() {
        let a = cap(
            401,
            &[
                ("content-type", "application/json"),
                ("content-length", "40"),
            ],
            "no",
        );
        let b = cap(
            401,
            &[
                ("content-length", "40"),
                ("content-type", "application/json"),
            ],
            "no",
        );
        pair_equal(&a, &b, "test").expect("the same headers in another order are the same headers");
    }

    /// A repeated header is still observable, so the multiset must COUNT rather
    /// than merely contain. This is why `stable_headers` sorts a `Vec` instead
    /// of collecting a set.
    #[test]
    fn a_repeated_header_is_not_equal_to_a_single_one() {
        let a = cap(401, &[("set-cookie", "x"), ("set-cookie", "x")], "no");
        let b = cap(401, &[("set-cookie", "x")], "no");
        let e = pair_equal(&a, &b, "C-XX").expect_err("one occurrence is not two");
        assert!(e.to_string().contains("BY HEADERS"), "{e}");
    }

    #[test]
    fn header_presence_is_case_insensitive() {
        let a = cap(401, &[("www-authenticate", "Basic")], "no");
        assert!(a.has_header("WWW-Authenticate"));
        assert!(!a.has_header("x-absent"));
    }
}
