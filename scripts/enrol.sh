#!/usr/bin/env bash
# The identity ceremony's second half: redeem an enrolment, keep nothing.
#
#   printf '%s' "$SECRET" | ./scripts/enrol.sh ESTATE_PASSWORD
#
# THE FIRST HALF IS NOT HERE, and cannot be. ADR-0492's admin path does not
# exist — there is no `/admin` on the gateway — so the enrolment itself is minted
# through `iam`'s gRPC, which is an in-cluster act. MIGRATION_NOTES.md holds that
# step; this script starts from the secret it produces.
#
# WHAT THIS PRESERVES, AND WHAT IT DOES NOT. It does NOT preserve ADR-0492's
# ceremony: one operator mints the enrolment, redeems it, and chooses the
# password, so the three roles the ceremony separates collapse onto one person.
# For a bot identity that collapse is the right trade — there is no second party
# to hold the other half — but calling it preservation would be a false claim of
# the kind ADR-0562 exists to forbid. What IS true and narrower: no long-lived
# bearer token is stored anywhere, and the credential the suite starts from is
# redeemed through the same `POST /auth/enrol` a person uses. The suite then
# begins every run with `POST /auth/login`, which is contract C-01.
#
# THE SECRET ARRIVES ON STDIN, NEVER IN ARGV. Anything in argv is visible in
# `ps` to every other process on the machine, and it lands in the shell history.
#
# NOTHING IS PRINTED AND NOTHING IS WRITTEN. The password is generated here,
# passed to the edge, pushed straight into the GitHub environment secret, and
# lost. Rotation is repeating the ceremony, not recovering this value.
set -euo pipefail

SECRET_NAME="${1:?usage: printf '%s' \"\$SECRET\" | $0 <secret-name> [environment]}"
ENVIRONMENT="${2:-estate}"
REPO="${ESTATE_REPO:-yadgarhq/estate}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$(sed -n 's/^host = "\(.*\)"$/\1/p' "${HERE}/reference.toml" | head -1)"
PORT="${ESTATE_EDGE_PORT:-$(sed -n 's/^port = \([0-9]*\)$/\1/p' "${HERE}/reference.toml" | head -1)}"
CA="${HERE}/ca/root.pem"

for tool in curl gh python3; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done

# `|| true` IS LOAD-BEARING, NOT DEFENSIVE NOISE. The documented invocation is
# `printf '%s' "$SECRET" | ...`, which sends NO trailing newline, so `read` hits
# EOF and returns 1 — and under `set -e` that killed this script before anything
# happened. `read` still ASSIGNS the partial line it consumed, so the value is
# there; the emptiness check below is what distinguishes "no newline" from
# "nothing on stdin at all".
read -r -s SECRET || true
[ -n "${SECRET}" ] || { echo "no enrolment secret on stdin" >&2; exit 1; }

# 32 bytes from the system CSPRNG, hex. Chosen here rather than by a person:
# a password a person can remember is one a person can reuse.
PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# `--resolve` when the edge is not on 443, so that the client still sends the
# external NAME as SNI and validates the same chain a real client validates.
RESOLVE=()
if [ -n "${ESTATE_EDGE_RESOLVE:-}" ]; then
  RESOLVE=(--resolve "${HOST}:${PORT}:${ESTATE_EDGE_RESOLVE}")
fi

# The body is built by python and piped in, so neither the secret nor the
# password is ever an argument to curl.
RESPONSE="$(
  SECRET="${SECRET}" PASSWORD="${PASSWORD}" python3 -c '
import json, os, sys
sys.stdout.write(json.dumps({"secret": os.environ["SECRET"], "password": os.environ["PASSWORD"]}))
' | curl -sS --fail-with-body --cacert "${CA}" "${RESOLVE[@]}" \
       -H 'content-type: application/json' \
       -X POST "https://${HOST}:${PORT}/auth/enrol" --data-binary @-
)"

USERNAME="$(printf '%s' "${RESPONSE}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["username"])')"

# STRAIGHT INTO THE ENVIRONMENT SECRET. `gh secret set` reads the value from
# stdin, so the password never becomes an argument and never touches a file.
#
# THERE IS NO `--body -`, AND THAT ABSENCE IS THE MECHANISM. `gh secret set`'s
# flag is `-b, --body string  The value for the secret (reads from standard
# input if not specified)`. There is no `-`-means-stdin convention here and no
# `--body-file`: a non-empty `--body` is taken literally and short-circuits the
# stdin read, so `--body -` would store the one-character string `-` as the
# password. That failure is silent in the worst way — the secret is PRESENT, so
# the suite's "a missing credential is not a failing contract" guard never
# fires, and the first run reports C-01 red against a single-use enrolment
# secret that has already been spent.
printf '%s' "${PASSWORD}" | gh secret set "${SECRET_NAME}" \
  --repo "${REPO}" --env "${ENVIRONMENT}"

unset PASSWORD SECRET

echo "Enrolled ${USERNAME}. ${SECRET_NAME} is set in the ${ENVIRONMENT} environment of ${REPO}."
echo "The password was not printed and was not written anywhere. Rotate by repeating the ceremony."
