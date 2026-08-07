#!/usr/bin/env bash
#
# End-to-end smoke test for the DIYDDNS backend.
#
# Builds both binaries, boots a throwaway server against a temp SQLite DB,
# claims the first admin, mints an enrollment code, enrolls the agent, makes
# it check in, and asserts the reported IP landed in the device's history.
# Every step is checked; the first failure exits non-zero naming the step.
#
#   Usage:  scripts/smoke-test.sh [--skip-discovery]
#           task smoke
#
#   NETWORK: by default the check-in step runs the real public-IP discovery
#   quorum, which makes outbound HTTPS calls to third-party providers. That
#   is deliberate — it is the path a real agent takes. Pass --skip-discovery
#   on an air-gapped machine to stop after enrollment; steps 1-9 still run,
#   but the check-in and history assertions are skipped.
#
#   Env:
#     SMOKE_PORT   listen port (default: random in 20000-29999)
#
#   Requires: go, curl, jq. No `timeout` (absent on macOS), no python.
#
# The server config is config.example.yaml at the repo root, with the
# install-specific values supplied as DIYDDNS_* env vars (env beats file in
# the loader's precedence). Deliberate: it keeps one config in the repo
# instead of two, so every smoke run also proves the shipped example boots.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

STEP="startup"
SERVER_PID=""
WORK=""

# --- plumbing ---------------------------------------------------------------

step() {
	STEP="$1"
	printf '==> %s\n' "$1"
}

fail() {
	printf '\nSMOKE FAIL [%s]: %s\n' "$STEP" "$1" >&2
	if [ -n "${SERVER_LOG:-}" ] && [ -f "${SERVER_LOG}" ]; then
		printf '\n--- last 30 lines of server log ---\n' >&2
		tail -n 30 "$SERVER_LOG" >&2
	fi
	exit 1
}

cleanup() {
	if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if [ -n "$WORK" ] && [ -d "$WORK" ]; then
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT

# http METHOD PATH [curl args...] — writes the body to $RESP, echoes the status.
http() {
	local method="$1" path="$2"
	shift 2
	curl -sS -o "$RESP" -w '%{http_code}' --max-time 15 \
		-X "$method" "$BASE_URL$path" "$@"
}

expect_status() {
	local want="$1" got="$2" what="$3"
	[ "$got" = "$want" ] ||
		fail "$what returned HTTP $got, want $want; body: $(cat "$RESP" 2>/dev/null)"
}

SKIP_DISCOVERY=0
for arg in "$@"; do
	case "$arg" in
	--skip-discovery) SKIP_DISCOVERY=1 ;;
	*) fail "unknown argument: $arg (only --skip-discovery is accepted)" ;;
	esac
done

for tool in go curl jq; do
	command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done

# --- session acquisition ----------------------------------------------------

# acquire_admin_session claims the first admin and obtains a browser session.
# On success it sets SESSION_COOKIE and CSRF_TOKEN, which every subsequent
# authenticated request uses.
#
# THE PLANNED PASSKEY WORK REPLACES THIS FUNCTION WHOLESALE: multi-passkey
# WebAuthn deletes POST /api/v1/auth/login and email/password auth entirely.
# The rest of this script depends only on the two variables set here, so the
# flip is an edit to this one function — do not inline any of it into the
# steps below.
acquire_admin_session() {
	step "scrape BOOTSTRAP_TOKEN from the server log"
	# The token is base64url (auth.RandToken uses RawURLEncoding): no padding,
	# alphabet [A-Za-z0-9_-], so it terminates at the first space.
	local token
	token="$(grep -o 'BOOTSTRAP_TOKEN=[A-Za-z0-9_-]*' "$SERVER_LOG" | head -n1 | cut -d= -f2)"
	[ -n "$token" ] || fail "no BOOTSTRAP_TOKEN=<token> line in the server log"

	step "POST /api/v1/auth/bootstrap (claim the first admin)"
	local status
	status="$(http POST /api/v1/auth/bootstrap \
		-H 'Content-Type: application/json' \
		-d "{\"token\":\"$token\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
	expect_status 200 "$status" "bootstrap"

	step "POST /api/v1/auth/login (obtain a session cookie)"
	local headers="$WORK/login.headers"
	status="$(http POST /api/v1/auth/login -D "$headers" \
		-H 'Content-Type: application/json' \
		-d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
	expect_status 200 "$status" "login"

	# Read the cookie out of the response headers rather than using curl's
	# cookie jar: the server sets Secure by default (auth.session.cookie_secure)
	# and curl refuses to send a Secure cookie back over plain HTTP. Parsing the
	# header lets the smoke run exercise the shipped default instead of
	# weakening the config to accommodate the test client.
	SESSION_COOKIE="$(tr -d '\r' <"$headers" |
		sed -n 's/^[Ss]et-[Cc]ookie: *\(diyddns_session=[^;]*\).*/\1/p' | head -n1)"
	[ -n "$SESSION_COOKIE" ] || fail "login response carried no diyddns_session cookie"

	step "GET /api/v1/auth/me (extract the CSRF token)"
	status="$(http GET /api/v1/auth/me -H "Cookie: $SESSION_COOKIE")"
	expect_status 200 "$status" "auth/me"
	CSRF_TOKEN="$(jq -r '.csrf // empty' "$RESP")"
	[ -n "$CSRF_TOKEN" ] || fail "auth/me response had no csrf field: $(cat "$RESP")"
}

# --- run --------------------------------------------------------------------

WORK="$(mktemp -d "${TMPDIR:-/tmp}/diyddns-smoke.XXXXXX")"
readonly RESP="$WORK/resp.body"
readonly SERVER_LOG="$WORK/server.log"
readonly CRED_FILE="$WORK/credentials.json"
readonly ADMIN_EMAIL="smoke-admin@example.com"
# Must clear auth.password.min_length (default 12).
readonly ADMIN_PASSWORD="smoke-test-password"

PORT="${SMOKE_PORT:-$((20000 + RANDOM % 10000))}"
readonly LISTEN="127.0.0.1:$PORT"
readonly BASE_URL="http://$LISTEN"

step "build both binaries"
go build -o "$WORK/diyddns-server" "$REPO_ROOT/cmd/diyddns-server" ||
	fail "go build diyddns-server"
go build -o "$WORK/diyddns-client" "$REPO_ROOT/cmd/diyddns-client" ||
	fail "go build diyddns-client"

step "start diyddns-server on $BASE_URL"
DIYDDNS_DATABASE_PATH="$WORK/diyddns.db" \
	DIYDDNS_SERVER_LISTEN="$LISTEN" \
	DIYDDNS_SERVER_BASE_URL="$BASE_URL" \
	DIYDDNS_AUTH_HMAC_SECRET_KEY="$(head -c 32 /dev/urandom | base64 | tr -d '\n')" \
	"$WORK/diyddns-server" serve --config "$REPO_ROOT/config.example.yaml" \
	>"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

step "wait for GET /healthz to return ok"
ready=0
for _ in $(seq 1 100); do
	kill -0 "$SERVER_PID" 2>/dev/null || fail "server exited before becoming ready"
	if [ "$(curl -fsS --max-time 2 "$BASE_URL/healthz" 2>/dev/null || true)" = "ok" ]; then
		ready=1
		break
	fi
	sleep 0.2
done
[ "$ready" = 1 ] || fail "server did not answer /healthz with ok within 20s"

acquire_admin_session

step "POST /api/v1/devices (mint an enrollment code)"
# The body field is "label"; "name" is rejected with 422.
status="$(http POST /api/v1/devices \
	-H "Cookie: $SESSION_COOKIE" \
	-H "X-CSRF-Token: $CSRF_TOKEN" \
	-H 'Content-Type: application/json' \
	-d '{"label":"smoketest"}')"
expect_status 200 "$status" "mint enrollment code"
CODE="$(jq -r '.code // empty' "$RESP")"
[ -n "$CODE" ] || fail "mint response had no code field: $(cat "$RESP")"
jq -e '.expires_at > 0' "$RESP" >/dev/null || fail "mint response had no expires_at"

step "diyddns-client enroll --code"
"$WORK/diyddns-client" enroll --code "$CODE" --server "$BASE_URL" \
	--credentials-file "$CRED_FILE" || fail "enroll --code"
[ -f "$CRED_FILE" ] || fail "enroll did not write $CRED_FILE"
case "$(uname -s)" in # BSD and GNU stat spell this differently
Darwin) mode="$(stat -f '%Lp' "$CRED_FILE")" ;;
*) mode="$(stat -c '%a' "$CRED_FILE")" ;;
esac
[ "$mode" = "600" ] || fail "credentials file mode is $mode, want 600"
DEVICE_ID="$(jq -r '.device_id // empty' "$CRED_FILE")"
[ -n "$DEVICE_ID" ] || fail "credentials file has no device_id"

if [ "$SKIP_DISCOVERY" = 1 ]; then
	printf '\n--skip-discovery: skipping check-in and history assertions.\n'
	printf 'SMOKE OK (enrollment path only)\n'
	exit 0
fi

step "diyddns-client run --once (public-IP discovery + check-in)"
RUN_LOG="$WORK/run.log"
"$WORK/diyddns-client" run --once --credentials-file "$CRED_FILE" \
	>"$RUN_LOG" 2>&1 || {
	cat "$RUN_LOG" >&2
	fail "run --once (needs outbound internet; use --skip-discovery offline)"
}
grep -q 'stored=true' "$RUN_LOG" || {
	cat "$RUN_LOG" >&2
	fail "check-in did not report stored=true"
}
REPORTED_IPV4="$(grep -o 'ipv4=[0-9.]*' "$RUN_LOG" | head -n1 | cut -d= -f2)"
[ -n "$REPORTED_IPV4" ] || {
	cat "$RUN_LOG" >&2
	fail "client reported no IPv4 (this smoke test needs IPv4 quorum)"
}
printf '    client reported ipv4=%s\n' "$REPORTED_IPV4"

step "GET /api/v1/devices/{id}/history (find the reported IP)"
status="$(http GET "/api/v1/devices/$DEVICE_ID/history" -H "Cookie: $SESSION_COOKIE")"
expect_status 200 "$status" "device history"
jq -e --arg ip "$REPORTED_IPV4" '[.rows[] | select(.ipv4 == $ip)] | length > 0' \
	"$RESP" >/dev/null || fail "no history row with ipv4=$REPORTED_IPV4: $(cat "$RESP")"

step "GET /api/v1/devices/{id} (current_ipv4 and last_seen_at populated)"
status="$(http GET "/api/v1/devices/$DEVICE_ID" -H "Cookie: $SESSION_COOKIE")"
expect_status 200 "$status" "get device"
jq -e --arg ip "$REPORTED_IPV4" '.current_ipv4 == $ip' "$RESP" >/dev/null ||
	fail "current_ipv4 != $REPORTED_IPV4: $(cat "$RESP")"
jq -e '.last_seen_at > 0' "$RESP" >/dev/null ||
	fail "last_seen_at not populated: $(cat "$RESP")"

printf '\nSMOKE OK\n'
