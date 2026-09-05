//! The smoke subset of the behavioural contract suite (ADR-0562).
//!
//! Nine of the ten smoke rows are here; C-18 is in `confinement.rs`, because it
//! reports as its own named check rather than folded into this verdict.
//!
//! **EVERY ROW IS `#[ignore]`, AND THAT IS NOT A SKIP.** These rows dial
//! `https://gateway.yadgar.internal` and need a credential. The estate's shared
//! CI runs `cargo test --all-features` on a GitHub-hosted runner with no route
//! to the reference cluster and no credential, so a row that ran there would
//! fail for the environment and teach everyone to ignore a red. They are run
//! deliberately, by `.github/workflows/smoke.yaml`, on the `estate-front`
//! runner, with `cargo test --test smoke -- --ignored`. `cargo test` still
//! PRINTS each one as ignored, so the subset is visible rather than invisible.
//!
//! **WHAT EACH ROW ENFORCES IS NAMED IN ITS OWN TEXT** (ADR-0562). A decision
//! whose behaviour cannot be observed from the front door is stated in
//! `UNOBSERVED.md` rather than tested by a shortcut.
//!
//! **A MISSING CREDENTIAL IS NOT A FAILING CONTRACT.** `Identity::primary`
//! errors with a message naming the ceremony that supplies the password. Read
//! the message before reading the row.

use anyhow::Result;
use estate_front::{Identity, Suite};
use estate_harness::client::Edge;
use estate_harness::{auth, mcp, pair_equal};
use serde_json::json;

// ---------------------------------------------------------------------------
// C-14 — ADR-0490/0504. The edge, and the trust path a real client walks.
// ---------------------------------------------------------------------------

/// C-14 (ADR-0490, ADR-0504): the edge serves the certificate real clients
/// validate, and does NOT serve one the public web PKI would accept.
///
/// Both halves matter and they fail for opposite reasons. The FIRST failing
/// means the edge is not serving the certificate a real client validates — the
/// leaf does not cover the name, or the chain does not terminate in the
/// committed root. The SECOND passing means something else is answering on the
/// name, or a publicly-trusted certificate is, and the whole suite would then be
/// validating a path no client of this estate uses.
///
/// This runs first among the smoke rows in reading order because everything
/// below it is meaningless if the thing answering is not the edge.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c14_the_edge_chains_to_the_committed_root_and_not_to_the_public_web_pki() -> Result<()> {
    let suite = Suite::open()?;

    let ours = mcp::post(
        &suite.edge,
        &suite.reference,
        &mcp::Caller::anonymous(),
        mcp::DISCOVER,
        json!({}),
    )
    .await
    .map_err(|e| {
        anyhow::anyhow!(
            "C-14 first half: the handshake against the COMMITTED root failed — {e}. \
             The edge is not serving the certificate a real client validates."
        )
    })?;
    anyhow::ensure!(
        ours.status == 200,
        "C-14: discover answered {}",
        ours.status
    );

    let public = Edge::trusting_public_web_pki(&suite.reference)?;
    let result = mcp::post(
        &public,
        &suite.reference,
        &mcp::Caller::anonymous(),
        mcp::DISCOVER,
        json!({}),
    )
    .await;
    anyhow::ensure!(
        result.is_err(),
        "C-14 second half: a client trusting only the Mozilla root bundle COMPLETED a handshake \
         with {}. Either something else is answering on the name, or the edge now serves a \
         publicly-trusted certificate — in both cases this suite would be validating a path no \
         client of this estate uses.",
        suite.edge.base()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C-01..C-03 — ADR-0507. The credential path, and the oracle it must not be.
// ---------------------------------------------------------------------------

/// C-01 (ADR-0507, D72): a real login answers 200 and discloses exactly one key.
///
/// The key set is asserted EXACTLY rather than "contains token". A response that
/// grew a second key would be one carrying credential material beyond the token
/// — the failure this row is watching for is disclosure, not absence.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c01_a_real_login_answers_a_token_and_nothing_else() -> Result<()> {
    let suite = Suite::open()?;
    let s = Identity::primary()?;

    let capture = auth::login(&suite.edge, &s.username, s.password()).await?;
    anyhow::ensure!(
        capture.status == 200,
        "C-01: login answered {} — {}. Nobody can authenticate.",
        capture.status,
        capture.body_str()
    );

    let body = capture.json()?;
    let keys: Vec<&str> = body
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    anyhow::ensure!(
        keys == ["token"],
        "C-01: the login body's key set is {keys:?}, not exactly [\"token\"]. \
         A second key is credential material leaking beside the token."
    );
    anyhow::ensure!(!auth::token_of(&capture)?.is_empty(), "C-01: empty token");
    Ok(())
}

/// C-02 (ADR-0507): a failed login discloses nothing about why it failed.
///
/// Three assertions, and each is a separate channel a caller can read: the
/// status is exactly the declared one, the body is byte-equal to the declared
/// constant, and the header name set is a SUBSET of the infrastructure allowlist
/// declared in `reference.toml`. The allowlist is a CLOSED SET — a header
/// outside it fails this row, and admitting a new one is a reviewed edit to that
/// file rather than a silent loosening here.
///
/// `WWW-Authenticate` is asserted absent by name as well, because a challenge
/// header is the specific disclosure ADR-0507's two-status collapse exists to
/// prevent.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c02_a_wrong_password_discloses_nothing() -> Result<()> {
    let suite = Suite::open()?;
    let s = Identity::primary()?;

    let capture = auth::login(&suite.edge, &s.username, "not-the-password").await?;
    assert_refusal_is_opaque(&suite, &capture, "C-02")
}

/// C-03 (ADR-0507 + ADR-0521's method): an unknown username and a known one with
/// a wrong password are ONE answer.
///
/// The two responses are captured and compared byte for byte. This is the whole
/// point: a row asserting "both were refused" passes against the version where
/// the unknown user takes a different path and answers differently. `iam` runs a
/// dummy verification for a username it has never seen so that both arms cost
/// the same and reach the same refusal; if that path is removed, an unauthenticated
/// caller learns which usernames exist.
///
/// **THE POSITIVE CONTROL IS THE FIRST CALL AND IT IS NOT CEREMONY.** This row
/// compares a KNOWN username against an unknown one. If `ESTATE_USERNAME` is
/// mistyped, or the identity is deleted, both arms are the unknown-user path,
/// they are trivially identical, and the row reports green having tested
/// nothing — the same trap C-18 already accepts and guards against by resolving
/// its targets first. Existence cannot be proved from a refusal here, because
/// indistinguishable refusals are the very property under test; the only proof
/// available from the front door is a login that SUCCEEDS. So the row logs in
/// with the real password first, and a failure there is reported as a broken
/// SUBJECT rather than as a broken contract.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c03_an_unknown_username_is_indistinguishable_from_a_wrong_password() -> Result<()> {
    let suite = Suite::open()?;
    let s = Identity::primary()?;

    let control = auth::login(&suite.edge, &s.username, s.password()).await?;
    anyhow::ensure!(
        control.status == 200,
        "C-03 POSITIVE CONTROL FAILED, so this row proved nothing about the contract: logging in \
         as {:?} with the real password answered {} — {}. That username must EXIST for the \
         comparison below to mean anything; if it does not, both arms are the unknown-user path, \
         they match trivially, and the row would report green. Check ESTATE_USERNAME and the \
         identity ceremony before reading this as an account-enumeration finding.",
        s.username,
        control.status,
        control.body_str()
    );

    let known = auth::login(&suite.edge, &s.username, "not-the-password").await?;
    let unknown = auth::login(
        &suite.edge,
        "estate-c03-this-username-was-never-created",
        "not-the-password",
    )
    .await?;

    assert_refusal_is_opaque(&suite, &unknown, "C-03")?;
    pair_equal(
        &known,
        &unknown,
        "C-03: an account-enumeration oracle — a caller learns which usernames exist",
    )
}

/// The shape every login refusal must have, asserted the same way for C-02 and
/// C-03 so the two rows cannot drift apart.
fn assert_refusal_is_opaque(
    suite: &Suite,
    capture: &estate_harness::Captured,
    row: &str,
) -> Result<()> {
    let declared = &suite.reference.login;
    anyhow::ensure!(
        capture.status == declared.refusal_status,
        "{row}: a failed login answered {} rather than {}. The two-status collapse is broken.",
        capture.status,
        declared.refusal_status
    );
    anyhow::ensure!(
        capture.body_str() == declared.refusal_body,
        "{row}: the refusal body is {:?}, not the declared constant {:?}.",
        capture.body_str(),
        declared.refusal_body
    );
    anyhow::ensure!(
        !capture.has_header("www-authenticate"),
        "{row}: the refusal carries WWW-Authenticate, which tells a caller which side of \
         verification failed."
    );
    let unexpected: Vec<String> = capture
        .header_names()
        .into_iter()
        .filter(|h| !declared.allowed_headers.contains(h))
        .collect();
    anyhow::ensure!(
        unexpected.is_empty(),
        "{row}: the refusal carries header(s) {unexpected:?}, which are not in the infrastructure \
         allowlist declared in reference.toml ({:?}). Admitting one is a reviewed edit to that \
         file, not a change here.",
        declared.allowed_headers
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C-04 — ADR-0511. A credential is resolved, never believed.
// ---------------------------------------------------------------------------

/// C-04 (ADR-0511): a bearer token nobody issued authenticates nobody.
///
/// **THE 401 IS THE WHOLE DETECTOR.** The follow-up `find_tasks` below is
/// corroboration and must be read as nothing more: if the junk token DID
/// authenticate, it authenticated as somebody who is not the suite identity, and
/// C-11's visibility rules would hide that task from the suite identity anyway.
/// A clean `find_tasks` is therefore exactly what both the healthy system and
/// the defective one produce. It is run and reported because a reader chasing a
/// red wants the corroborating call in the log, not because it decides anything.
///
/// The defect this names is the one ADR-0511 records verbatim: an earlier
/// revision authenticated EVERY token.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c04_a_junk_bearer_token_authenticates_nobody() -> Result<()> {
    let suite = Suite::open()?;
    let junk = mcp::Caller::bearer(auth::junk_bearer(), suite.project.clone());

    let capture = mcp::tools_call(
        &suite.edge,
        &suite.reference,
        &junk,
        "create_task",
        json!({ "title": format!("estate C-04 {} MUST NOT EXIST", suite.project) }),
    )
    .await?;

    anyhow::ensure!(
        capture.status == 401,
        "C-04: a 64-byte random bearer token was answered {} rather than 401 — {}. \
         Junk credentials work.",
        capture.status,
        capture.body_str()
    );

    // CORROBORATION ONLY, AND IT CANNOT REDDEN THIS ROW. The 401 above already
    // decided the verdict. Everything below needs a credential and a login, and
    // a `?` on any of them would fail C-04 for a MISSING CREDENTIAL — reddening
    // the row its own detector just passed, which is precisely what the doc
    // comment says must not happen. A corroborating call that could not run is a
    // missing log line, so the failure is printed rather than propagated.
    match corroborate_c04(&suite).await {
        Ok(status) => eprintln!(
            "C-04 corroboration (not an assertion): find_tasks as the suite identity in {} \
             answered {status}",
            suite.project
        ),
        Err(e) => eprintln!(
            "C-04 corroboration could not run, which is NOT a failure of this row — the 401 above \
             is the whole detector: {e}"
        ),
    }
    Ok(())
}

/// C-04's corroborating call, in its own function so that every `?` inside it
/// lands in a `Result` the row DISCARDS. See the call site.
async fn corroborate_c04(suite: &Suite) -> Result<u16> {
    let s = Identity::primary()?;
    let token = suite.token_for(&s).await?;
    let caller = mcp::Caller::bearer(token, suite.project.clone());
    let listed = mcp::tools_call(
        &suite.edge,
        &suite.reference,
        &caller,
        "find_tasks",
        json!({}),
    )
    .await?;
    Ok(listed.status)
}

// ---------------------------------------------------------------------------
// C-06, C-13 — the surface, and the protocol every real client speaks.
// ---------------------------------------------------------------------------

/// C-06 (ADR-0492 negative, D67): the tool surface is a CLOSED SET.
///
/// Equality on the whole set, never absence checks for known-bad names. An
/// absence check passes forever, including the day someone ships `manage_users`;
/// closed-set equality fails loudly on any addition. The cost is accepted
/// deliberately: every legitimate new tool breaks this row and forces a one-line
/// edit to `reference.toml`, and THAT edit is the review ADR-0562 wants to force.
/// If the new name is administrative, privilege escalation is one prompt
/// injection away.
///
/// No credential: `tools/list` takes none, so this row still means something on
/// a run where C-01 has already failed.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c06_the_tool_surface_is_exactly_the_declared_closed_set() -> Result<()> {
    let suite = Suite::open()?;
    let capture = mcp::post(
        &suite.edge,
        &suite.reference,
        &mcp::Caller::anonymous(),
        mcp::TOOLS_LIST,
        json!({}),
    )
    .await?;
    anyhow::ensure!(
        capture.status == 200,
        "C-06: tools/list answered {}",
        capture.status
    );

    let body = capture.json()?;
    // NOT `filter_map`. A tool object whose `name` is absent or is not a string
    // would be DROPPED by a filtering read — silently shrinking the very set
    // this row compares, so an unreviewed tool could arrive wearing a malformed
    // name and closed-set equality would still hold. Closed-set equality is the
    // entire value of C-06, so an unreadable name fails the row.
    let mut served: Vec<String> = Vec::new();
    for tool in body["result"]["tools"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("C-06: no tools array in {}", capture.body_str()))?
    {
        let name = tool["name"].as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "C-06: a served tool has no string `name` — {tool}. Skipping it would shrink the \
                 set this row compares and let an unreviewed tool pass the closed-set check."
            )
        })?;
        served.push(name.to_string());
    }
    served.sort();
    let mut declared = suite.reference.mcp.tools.clone();
    declared.sort();

    anyhow::ensure!(
        served == declared,
        "C-06: the served tool set is {served:?}; reference.toml declares {declared:?}. \
         A tool appeared or vanished without this suite being deliberately updated."
    );
    Ok(())
}

/// C-13 (D75, MCP revision 2026-07-28): the handshake every real client makes.
///
/// Three assertions, and the third is the one that was wrong in an earlier draft
/// of this suite. **There is no `initialize` on this server.** The 2026-07-28
/// revision removed the handshake, so `initialize` falls to the unknown-method
/// arm and answers HTTP 200 with JSON-RPC `-32601`. This row asserts that,
/// rather than asserting a handshake that does not exist.
///
/// An unknown TOOL is likewise a JSON-RPC error inside a 200, not a 500 — the
/// name is refused before anything else happens, so a caller cannot mint a
/// metric series by inventing tool names either.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c13_the_mcp_baseline_answers_as_the_revision_defines() -> Result<()> {
    let suite = Suite::open()?;
    let anon = mcp::Caller::anonymous();
    let r = &suite.reference;

    let discover = mcp::post(&suite.edge, r, &anon, mcp::DISCOVER, json!({})).await?;
    anyhow::ensure!(
        discover.status == 200,
        "C-13: discover answered {}",
        discover.status
    );
    let d = discover.json()?;
    let result = &d["result"];
    anyhow::ensure!(
        result["supportedVersions"]
            .as_array()
            .is_some_and(|v| v.iter().any(|x| x == &json!(r.mcp.protocol_version))),
        "C-13: supportedVersions {} does not contain {}",
        result["supportedVersions"],
        r.mcp.protocol_version
    );
    anyhow::ensure!(
        result["capabilities"]["tools"].is_object(),
        "C-13: capabilities.tools is absent"
    );
    anyhow::ensure!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == json!(r.mcp.server_name),
        "C-13: serverInfo name is {}, not {}",
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        r.mcp.server_name
    );
    anyhow::ensure!(
        result["resultType"] == json!(r.mcp.result_type),
        "C-13: resultType is {}, not {}",
        result["resultType"],
        r.mcp.result_type
    );

    let unknown_tool = mcp::tools_call(&suite.edge, r, &anon, "no_such_tool", json!({})).await?;
    anyhow::ensure!(
        unknown_tool.status == 200 && unknown_tool.json()?["error"]["code"] == json!(-32602),
        "C-13: an unknown tool answered {} — {}. It must be a JSON-RPC error, not a fault.",
        unknown_tool.status,
        unknown_tool.body_str()
    );

    let initialize = mcp::post(&suite.edge, r, &anon, "initialize", json!({})).await?;
    anyhow::ensure!(
        initialize.status == 200 && initialize.json()?["error"]["code"] == json!(-32601),
        "C-13: `initialize` answered {} — {}. This revision has no handshake; the name must fall \
         to the unknown-method arm.",
        initialize.status,
        initialize.body_str()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C-10, C-11 — ADR-0522. The read path, and who may walk it.
// ---------------------------------------------------------------------------

/// C-10 (ADR-0522's shipped default): the spine, end to end.
///
/// Edge → login → attestation → tool dispatch → task-db read path, in one row.
/// It is also **the canary for ADR-0522's eager whole-read refusal**: if the
/// organisation setting resolution breaks, task-db answers `INVALID_ARGUMENT`
/// ("a store may not choose one on its behalf") to every read in the
/// organisation, and this row is where that first shows.
///
/// The shipped default it exercises is narrow and worth naming: an owner reading
/// their own record with the lock ENGAGED. The arm that makes the setting a
/// setting is not testable from the front door; `UNOBSERVED.md` says so and says
/// where it is owed instead.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c10_a_task_round_trips_through_the_whole_spine() -> Result<()> {
    let suite = Suite::open()?;
    let s = Identity::primary()?;
    let caller = mcp::Caller::bearer(suite.token_for(&s).await?, suite.project.clone());
    let r = &suite.reference;

    let title = format!("estate C-10 {}", suite.project);
    let created = mcp::tools_call(
        &suite.edge,
        r,
        &caller,
        "create_task",
        json!({ "title": title }),
    )
    .await?;
    let made = mcp::structured(&created)?;
    let id = made["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("C-10: create_task returned no id: {made}"))?
        .to_string();
    let number = made["number"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("C-10: create_task returned no number: {made}"))?;

    let by_id = mcp::structured(
        &mcp::tools_call(&suite.edge, r, &caller, "read_task", json!({ "id": id })).await?,
    )?;
    anyhow::ensure!(
        by_id["title"] == json!(title),
        "C-10: the title did not round-trip by id — {by_id}"
    );

    let by_number = mcp::structured(
        &mcp::tools_call(
            &suite.edge,
            r,
            &caller,
            "read_task",
            json!({ "number": number }),
        )
        .await?,
    )?;
    anyhow::ensure!(
        by_number["title"] == json!(title),
        "C-10: the title did not round-trip by number — {by_number}"
    );

    let found =
        mcp::structured(&mcp::tools_call(&suite.edge, r, &caller, "find_tasks", json!({})).await?)?;
    anyhow::ensure!(
        found["tasks"]
            .as_array()
            .is_some_and(|t| t.iter().any(|x| x["id"] == json!(id))),
        "C-10: find_tasks in {} did not list the task it just created — {found}",
        suite.project
    );
    Ok(())
}

/// C-11 (ADR-0522's refusal side, by ADR-0521's method): a record that is not
/// yours reads exactly like a record that does not exist.
///
/// Two failures live here and they are different. (a) failing means reach
/// enforcement is off and any authenticated user reads anyone's records. The
/// PAIR failing means the two refusals are distinguishable, which is a
/// record-existence oracle across users — a caller learns that an id it may not
/// read nonetheless names something.
///
/// (b)'s id is derived from (a)'s by rewriting its trailing characters, in the
/// character class each one already belongs to. A hand-written "obviously fake"
/// id would be refused by validation rather than by the reach rule, and the pair
/// would then compare two different mechanisms. What that derivation gives is
/// narrower than "well-formed by construction", which an earlier revision of
/// this comment claimed: it preserves the LENGTH, the separators and the
/// character class of every rewritten character, and for the id format actually
/// in use — `yadgar:task:<UUIDv7>`, whose tail is lowercase hex — that is enough
/// to leave a well-formed identifier. It is not a proof for a format this row
/// has never seen. See [`rewrite_tail`].
///
/// **S2 IS PROVED TO BE A WORKING CALLER FIRST.** (a) asserts only that a read
/// FAILS, which a 401, a 500 or an organisation-scope refusal all satisfy. An S2
/// that can read nothing at all would refuse (a) and (b) identically, the pair
/// would match, and the row would report green while claiming to have verified
/// cross-user isolation. So S2 creates and reads its OWN task before either
/// refusal is measured, and a failure there is reported as a broken SUBJECT
/// rather than as a broken contract.
#[tokio::test]
#[ignore = "dials the reference cluster edge; run via `cargo test --test smoke -- --ignored`"]
async fn c11_another_users_record_is_indistinguishable_from_no_record() -> Result<()> {
    let suite = Suite::open()?;
    let r = &suite.reference;
    let s = Identity::primary()?;
    let s2 = Identity::secondary()?;

    let owner = mcp::Caller::bearer(suite.token_for(&s).await?, suite.project.clone());
    let created = mcp::tools_call(
        &suite.edge,
        r,
        &owner,
        "create_task",
        json!({ "title": format!("estate C-11 {}", suite.project) }),
    )
    .await?;
    let id = mcp::structured(&created)?["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("C-11: create_task returned no id"))?
        .to_string();

    let other = mcp::Caller::bearer(suite.token_for(&s2).await?, suite.project.clone());

    // THE POSITIVE CONTROL. Everything below asserts that S2 is REFUSED; this is
    // the one call proving S2 can be answered at all. Without it the row cannot
    // tell isolation from a broken second identity, and the broken one is green.
    let control = mcp::tools_call(
        &suite.edge,
        r,
        &other,
        "create_task",
        json!({ "title": format!("estate C-11 control {}", suite.project) }),
    )
    .await?;
    let made = mcp::structured(&control).map_err(|e| {
        anyhow::anyhow!(
            "C-11 POSITIVE CONTROL FAILED, so this row proved nothing: the second identity \
             could not create a task of its own — {e}. Every assertion below is that S2 is \
             REFUSED, and an S2 that is refused everything satisfies them while verifying no \
             isolation whatsoever. Check ESTATE_PASSWORD_2 and the identity ceremony before \
             reading this run as evidence about reach enforcement."
        )
    })?;
    let control_id = made["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("C-11 positive control: create_task returned no id"))?
        .to_string();
    let control_read = mcp::tools_call(
        &suite.edge,
        r,
        &other,
        "read_task",
        json!({ "id": control_id.clone() }),
    )
    .await?;
    let read_back = mcp::structured(&control_read).map_err(|e| {
        anyhow::anyhow!(
            "C-11 POSITIVE CONTROL FAILED, so this row proved nothing: the second identity \
             could not read the task it had just created — {e}. S2 is not a functioning \
             caller, and a caller that can read nothing refuses both arms below \
             identically."
        )
    })?;
    anyhow::ensure!(
        read_back["id"] == json!(control_id),
        "C-11 positive control: reading S2's own task returned {read_back}, not {control_id}"
    );

    let not_yours = mcp::tools_call(
        &suite.edge,
        r,
        &other,
        "read_task",
        json!({ "id": id.clone() }),
    )
    .await?;
    anyhow::ensure!(
        mcp::structured(&not_yours).is_err(),
        "C-11(a): the second identity READ the first identity's private record. Reach \
         enforcement is off — any authenticated user reads anyone's records. Body: {}",
        not_yours.body_str()
    );

    let never_issued = rewrite_tail(&id);
    anyhow::ensure!(
        never_issued != id,
        "C-11: the derived id must differ from the real one"
    );
    let absent = mcp::tools_call(
        &suite.edge,
        r,
        &other,
        "read_task",
        json!({ "id": never_issued }),
    )
    .await?;

    pair_equal(
        &not_yours,
        &absent,
        "C-11: a record-existence oracle — `exists but not yours` is distinguishable from \
         `does not exist`",
    )
}

/// An identifier that was never issued, built from one that was.
///
/// The last eight characters are rotated within their own alphabet, so the
/// length, the separators and each character's class are preserved and only the
/// identity changes.
///
/// **HEX IS ROTATED AS HEX, AND THAT ORDERING IS THE POINT.** Task ids are
/// `yadgar:task:<UUIDv7>` (`task-db/src/write.rs`: `Uuid::now_v7()`), so the
/// tail is lowercase hex. An earlier revision rotated letters within `a`–`z`,
/// which sends `b→g`, `c→h`, `d→i`, `e→j` and `f→k` — all outside hex. With
/// eight characters drawn from a uniform tail, the chance of at least one
/// landing in `{b,c,d,e,f}` is about 95%, so the derived id was NOT a UUID on
/// roughly nineteen runs in twenty. Nothing validates the id today, which is the
/// only reason that was harmless: add a URN-shape check on the read path and
/// C-11 turns red comparing an `INVALID_ARGUMENT` against a `not_found` — a
/// false red that reads exactly like a discovered oracle, which is the most
/// expensive kind of wrong answer this suite can give. `(v + 5) % 16` keeps hex
/// in hex and has no fixed point, so every rewritten character does change.
///
/// Only the tail moves, so a UUID's version and variant nibbles are untouched.
fn rewrite_tail(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    let start = chars.len().saturating_sub(8);
    chars
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i < start {
                *c
            } else if let Some(v) = c.to_digit(16) {
                // Hex FIRST, so `0`–`9` and `a`–`f` stay inside hex rather than
                // being rotated out of it by the decimal or alphabetic arm.
                let rotated = char::from_digit((v + 5) % 16, 16).expect("a value below 16");
                if c.is_ascii_uppercase() {
                    rotated.to_ascii_uppercase()
                } else {
                    rotated
                }
            } else if c.is_ascii_lowercase() {
                char::from(b'a' + (*c as u8 - b'a' + 5) % 26)
            } else if c.is_ascii_uppercase() {
                char::from(b'A' + (*c as u8 - b'A' + 5) % 26)
            } else {
                *c
            }
        })
        .collect()
}

mod helper_tests {
    use super::rewrite_tail;

    /// THE FIXTURE IS A REAL ID, not an invented one. `task-db` mints
    /// `yadgar:task:{}` from `Uuid::now_v7()`, so the tail this helper rewrites
    /// is lowercase hex. A fixture in some other alphabet would let these tests
    /// pass while documenting a format the helper never sees — which is how the
    /// non-hex rotation survived review in the first place.
    const A_REAL_TASK_ID: &str = "yadgar:task:0198b3c4-7d2e-7f1a-9c60-3ab5de92f4c7";

    /// The derived id must be a different id of the same shape — not a different
    /// LENGTH, and not a string with a character class the original never had.
    #[test]
    fn the_derived_id_keeps_the_shape_and_changes_the_identity() {
        let derived = rewrite_tail(A_REAL_TASK_ID);
        assert_ne!(A_REAL_TASK_ID, derived);
        assert_eq!(A_REAL_TASK_ID.len(), derived.len());
        assert_eq!(
            &A_REAL_TASK_ID[..A_REAL_TASK_ID.len() - 8],
            &derived[..derived.len() - 8]
        );
    }

    /// THE ROW'S CORRECTNESS RESTS ON THIS ONE. A hex tail must stay hex: an id
    /// that is no longer a UUID would be refused by validation rather than by
    /// the reach rule, and C-11 would then compare two different mechanisms and
    /// report the difference as an oracle.
    #[test]
    fn a_hex_tail_stays_hex_and_every_character_changes() {
        let derived = rewrite_tail(A_REAL_TASK_ID);
        let tail = &derived[derived.len() - 8..];
        assert!(
            tail.chars().all(|c| c.is_ascii_hexdigit()),
            "the rewritten tail {tail} left the hex alphabet"
        );
        for (a, b) in A_REAL_TASK_ID
            .chars()
            .rev()
            .zip(derived.chars().rev())
            .take(8)
        {
            assert_ne!(a, b, "`(v + 5) % 16` has no fixed point");
        }
        // Every hex character, in both cases, and the rotation stays inside hex.
        for c in "0123456789abcdefABCDEF".chars() {
            let padded = format!("yadgar:task:xxxxxxx{c}");
            let out = rewrite_tail(&padded).chars().last().expect("non-empty");
            assert!(out.is_ascii_hexdigit(), "{c} rotated to {out}");
            assert_ne!(c, out);
            // Case is carried across only where there is a case to carry: `B`
            // rotates to `0`, which has none. What must never happen is a
            // letter changing case, which would break a format that is
            // case-sensitive.
            if out.is_ascii_alphabetic() {
                assert_eq!(
                    c.is_ascii_uppercase(),
                    out.is_ascii_uppercase(),
                    "{c} rotated to {out}, changing case"
                );
            }
        }
    }

    /// Separators inside the rewritten tail survive, so a dashed or colonned
    /// format is not turned into something validation would refuse outright.
    #[test]
    fn separators_in_the_tail_are_preserved() {
        let derived = rewrite_tail("urn:x:0a-1b-2c3d");
        assert!(derived.contains('-'), "{derived}");
        assert_eq!(derived.matches('-').count(), 2, "{derived}");
    }
}
