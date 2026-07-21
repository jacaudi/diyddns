# Plan 10 — Multi-passkey WebAuthn local auth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. All subagents use TDD (`superpowers:test-driven-development`) and verify before completion (`superpowers:verification-before-completion`).

**Design:** `docs/designs/2026-07-21-diyddns-10-passkeys-local-auth-design.md` (SGE-reviewed, all findings folded).

**Goal:** Replace local password authentication (argon2id) with multi-passkey WebAuthn + OIDC (clean break), including recovery/invite grants, a minimal server-rendered auth UI, and an SMTP subsystem.

**Architecture:** Passkey ceremonies run through `go-webauthn/webauthn` in a new `PasskeyService`, storing each credential as its own `webauthn.Credential` JSON blob. Discoverable (usernameless) login resolves the user by an opaque per-user `webauthn_handle` and mints the **same** cookie session the removed password login did (`SessionManager.Create`). Invites and recovery share one single-use hashed **registration-grant** token (`account_recovery_tokens`). All new machinery is added **additively** alongside the existing password auth; password auth (and the `password_hash` column) is removed only in Task 10, once passkey login already works — so the module compiles and every test passes at every task boundary.

**Tech Stack:** Go 1.25.7, `github.com/go-webauthn/webauthn` (pure-Go, **new** dep, server-only), huma v2.38.0, goose migrations (`modernc.org/sqlite`), stdlib `net/smtp` + `html/template` + vendored htmx-free JS helper, cobra/viper.

## Global Constraints

- **Pure Go, no CGO.** `go-webauthn` is pure-Go and **server-only**: it must NOT reach `cmd/diyddns-client`. `cmd/diyddns-client/deps_test.go` stays UNCHANGED and green (assert no `go-webauthn`/`webauthn` in the client binary).
- Go **1.25.7**; stdlib `testing`, **table-driven**, run with `-race`; wrap errors with `%w`.
- **Never log secrets:** SMTP password, recovery/invite tokens (log only a hash/prefix), the bootstrap token (existing behavior), session cookies, the sealed challenge cookie. WebAuthn public keys/credential ids are not secret but are not printed.
- **Full `golangci-lint` per task** (not just `go vet`) — gosec surfaces module-wide (Plan 06 lesson). `nolint` needs a rule id + reason: `// #nosec <ID> -- <reason>` (see `internal/store/audit_log.go`).
- Migrations wrap statements in `-- +goose StatementBegin/End`; every `ON DELETE` action is chosen deliberately (Plan 02 FK lesson).
- Additive-over-seams: reuse `SessionManager`, `auth.SealWithAAD`/`OpenWithAAD`, `auth.RandToken`, `csrfMiddleware`/`sessionMiddleware`/`adminMiddleware`, `Bootstrap.Consume`, `AuditSink`, goose embed. Do NOT rework HMAC device auth or OIDC.
- Dependencies are added in the task that first imports them (`go mod tidy` prunes unimported): `go-webauthn` in Task 5.

## Test Harness Reference (real helpers — reuse, do not reinvent)

- **store tests** (`package store`, `internal/store/*_test.go`): `newTestStore(t) (*Store, context.Context)` — fresh `:memory:` store + ctx.
- **service tests** (`package service`, `internal/server/service/*_test.go`): `openTestStore(t) *store.Store`; `discardLogger() *slog.Logger`; `newTestSessionManager(st) *auth.SessionManager`; construct an `AuditSink` via the existing test sink pattern in `*_test.go` (grep `AuditSink` in service tests).
- **api tests** (`package api_test`, `internal/server/api/*_test.go`): `newFullHarness(t) fullHarness` (wires the full service layer + returns `.srv *httptest.Server` and helpers); `newAPIServer(t)`; `memStore(t) *store.Store`; `postJSON(t, url, body) (status, respBody)`; `doJSON(t, method, url, body, cookie, csrf) (status, header, respBody)`; `findCookie(header, name) *http.Cookie`; `discardLogger()`. EXTEND `newFullHarness` when adding deps — do not fork it.
- **server tests** (`package server`, `internal/server/server_test.go`): black-box via `server.Handler(cfg, st, log)`.

## Library Verification (applies to Tasks 5–7 — do this first in Task 5)

`go-webauthn` has **no exported virtual authenticator**. For deterministic ceremony tests use the test-only dep **`github.com/descope/virtualwebauthn`** (server-test-only; never imported by non-test code, so the client guard is unaffected). In **Task 5 Step 0**, pin `go-webauthn` + `virtualwebauthn`, write one spike test that drives a full register→login round-trip through the real `PasskeyService`, and confirm the exact `virtualwebauthn` API (`NewRelyingParty`, `NewAuthenticator`, `NewCredential`, `ParseAttestationOptions`/`CreateAttestationResponse`, `ParseAssertionOptions`/`CreateAssertionResponse`) against the pinned version before writing the rest. Verified go-webauthn signatures this plan is built on (pkg.go.dev, 2026-07-21):

```go
func New(config *Config) (*WebAuthn, error)  // Config{RPID, RPDisplayName, RPOrigins []string, AttestationPreference protocol.ConveyancePreference, AuthenticatorSelection protocol.AuthenticatorSelection, Timeouts TimeoutsConfig}
type User interface { WebAuthnID() []byte; WebAuthnName() string; WebAuthnDisplayName() string; WebAuthnCredentials() []Credential; WebAuthnIcon() string }
func (w *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (*protocol.CredentialCreation, *SessionData, error)
func (w *WebAuthn) FinishRegistration(user User, session SessionData, r *http.Request) (*Credential, error)
func (w *WebAuthn) BeginDiscoverableLogin(opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)
func (w *WebAuthn) FinishDiscoverableLogin(handler DiscoverableUserHandler, session SessionData, r *http.Request) (*Credential, error)
type DiscoverableUserHandler func(rawID, userHandle []byte) (User, error)
// Credential has json tags (ID, PublicKey, Transport, Flags, Authenticator{AAGUID, SignCount, CloneWarning}, Attestation) → json-marshal/unmarshal is lossless.
// Options: WithConveyancePreference(protocol.PreferNoAttestation), WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred), WithUserVerification(protocol.VerificationPreferred).
```

`FinishDiscoverableLogin` returns only the credential; capture the resolved `User` inside the `DiscoverableUserHandler` closure (the handler looks up the user by `userHandle == webauthn_handle`).

---

## Storage refinement vs design §3

Store each passkey as the full `webauthn.Credential` **JSON blob** (`credential_json BLOB`), not hand-mapped columns: the library needs the complete `Credential` (PublicKey, Flags, Authenticator, Attestation) to verify a login, and round-tripping its own JSON is lossless and version-robust. Columns kept for lookup/display: `credential_id` (PK, = `Credential.ID`), `user_id`, `name`, `aaguid` (for the UI hint, denormalized), `created_at`, `last_used_at`. This supersedes the design's per-field columns (`public_key`/`sign_count`/`transports`) — they live inside `credential_json`.

---

## Task 1: Store — migration 00003 (additive) + `WebAuthnCredentialRepo` + user handle methods

**Files:**
- Create: `migrations/00003_passkeys.sql`
- Create: `internal/store/webauthn_credentials.go`
- Create: `internal/store/webauthn_credentials_test.go`
- Modify: `internal/store/users.go` (add handle methods only — do NOT touch `password_hash` yet)
- Test: `internal/store/users_test.go` (add handle test)

**Interfaces:**
- Produces: `type WebAuthnCredential struct { CredentialID []byte; UserID string; CredentialJSON []byte; Name string; AAGUID []byte; CreatedAt, LastUsedAt int64 }`; `(*Store).WebAuthnCredentials() *WebAuthnCredentialRepo`; methods `Create(ctx, WebAuthnCredential) (WebAuthnCredential, error)`, `ListByUser(ctx, userID) ([]WebAuthnCredential, error)`, `GetByID(ctx, credentialID []byte) (WebAuthnCredential, error)`, `Rename(ctx, credentialID []byte, name string) error`, `Delete(ctx, credentialID []byte) error`, `DeleteAllByUser(ctx, userID string) (int, error)`, `Update(ctx, WebAuthnCredential) error` (re-persists credential_json + last_used_at after a login). `(*UserRepo).SetWebAuthnHandle(ctx, userID string, handle []byte) error`, `GetByWebAuthnHandle(ctx, handle []byte) (User, error)`, `CountWebAuthnCredentials` via the repo above.
- Consumes: existing `scanString`/`nullIf*`/`ErrConflict`/`ErrNotFound`/`NowUnix`/`NewID` idioms.

- [ ] **Step 1: Write the migration.** `migrations/00003_passkeys.sql` — Up wraps the two `CREATE TABLE` + index + `ALTER TABLE users ADD COLUMN webauthn_handle BLOB` in `-- +goose StatementBegin/End`. **Do NOT drop `password_hash` here** (Task 10 edits this same unreleased 00003 file to add the `DROP COLUMN`). This split-across-tasks edit is safe because tests run a fresh `:memory:` DB that always applies the current 00003 whole, and goose does no checksum validation; the only caveat (M4) — a *file-backed dev DB* migrated at T1 will not re-run version 3, so its `password_hash` won't drop until recreated — is acceptable given no releases exist. Down: `DROP TABLE account_recovery_tokens; ALTER TABLE users DROP COLUMN webauthn_handle; DROP TABLE webauthn_credentials;` (both wrapped).

```sql
-- +goose Up
-- +goose StatementBegin
CREATE TABLE webauthn_credentials (
    credential_id   BLOB PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_json BLOB NOT NULL,
    name            TEXT NOT NULL,
    aaguid          BLOB,
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

ALTER TABLE users ADD COLUMN webauthn_handle BLOB;

CREATE TABLE account_recovery_tokens (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    used_at      INTEGER
);
CREATE INDEX account_recovery_tokens_expires ON account_recovery_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS account_recovery_tokens;
ALTER TABLE users DROP COLUMN webauthn_handle;
DROP TABLE IF EXISTS webauthn_credentials;
-- +goose StatementEnd
```

- [ ] **Step 2: Write failing repo tests** (`webauthn_credentials_test.go`, table-driven): Create+GetByID round-trip (bytes preserved); ListByUser ordering by created_at; Rename; Delete (ErrNotFound on missing); **DeleteAllByUser returns count**; **user-delete cascades** (create user+cred, `Users().Delete`, assert `GetByID` → ErrNotFound); Update re-persists credential_json + last_used_at. Handle test in `users_test.go`: `SetWebAuthnHandle` then `GetByWebAuthnHandle` returns the user; unknown handle → ErrNotFound. Use `newTestStore(t)`.
- [ ] **Step 3: Run — expect FAIL** (`go test ./internal/store/... -run WebAuthn -v` → undefined symbols).
- [ ] **Step 4: Implement** `webauthn_credentials.go` mirroring `enrollment_codes.go` idioms (const column list, `scanWebAuthnCredential`, `ExecContext` with `?` placeholders, `isUniqueViolation`→`ErrConflict`, `RowsAffected`→`ErrNotFound`). Add the two `UserRepo` handle methods to `users.go` (a targeted `UPDATE users SET webauthn_handle=? WHERE id=?` and a `SELECT ... WHERE webauthn_handle=?`; note `nullIfEmpty`-style handling — a NULL/empty handle must never match, so `GetByWebAuthnHandle` rejects an empty arg before querying).
- [ ] **Step 5: Run — expect PASS** (`go test ./internal/store/... -race`).
- [ ] **Step 6: Lint + commit.** `golangci-lint run ./internal/store/...`; `git add migrations/00003_passkeys.sql internal/store/webauthn_credentials*.go internal/store/users*.go && git commit -m "feat(store): add webauthn_credentials + recovery-token tables (migration 00003) and user webauthn_handle"`

---

## Task 2: Store — `AccountRecoveryRepo` (registration grants)

**Files:** Create `internal/store/account_recovery.go` + `_test.go`.

**Interfaces:**
- Produces: `type RecoveryToken struct { TokenHash, UserID, Reason string; ExpiresAt, UsedAt int64 }`; `(*Store).AccountRecovery() *AccountRecoveryRepo`; `Create(ctx, RecoveryToken) error`; `Consume(ctx, tokenHash string, now int64) (RecoveryToken, error)` (atomic single-use: `UPDATE ... SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, `RowsAffected==0`→`ErrNotFound`, then `Get`); `PruneExpired(ctx, now int64) (int, error)`.

- [ ] **Step 1: Failing tests** mirroring `enrollment_codes_test.go`: Create+Consume happy path returns the row with `reason`; Consume of an expired/used/unknown token → ErrNotFound; **double-Consume**: first succeeds, second → ErrNotFound (atomic gate); PruneExpired deletes only expired+unused, returns count; user-delete cascade.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `account_recovery.go` mirroring `enrollment_codes.go` (`Consume` = the exact atomic UPDATE pattern from `EnrollmentCodeRepo.Consume`).
- [ ] **Step 4: Run — expect PASS** (`-race`).
- [ ] **Step 5: Lint + commit** (`feat(store): add account_recovery_tokens repo (single-use registration grants)`).

---

## Task 3: Config — `auth.webauthn.*`, `auth.hide_local_login_ui`, `email.*`

**Files:** Modify `internal/config/config.go`; Test `internal/config/config_test.go`.

**Interfaces:**
- Produces: `WebAuthnCfg{RPID, RPOrigin, RPDisplayName string; Timeout time.Duration}` on `Auth`; `Auth.HideLocalLoginUI bool`; top-level `Server.Email EmailSection{Enabled bool; Host string; Port int; Username, Password, From, TLS string}`. Helper `(Auth) ResolveWebAuthn(baseURL string) (rpID, rpOrigin string, err error)` — derives RP ID (host of baseURL) + origin (scheme://host[:port]) when the explicit fields are empty; returns an error used by fail-closed startup when neither is resolvable.
- Consumes: existing `keyDefaults` map + `validateOIDC` extraction pattern.

- [ ] **Step 1: Failing tests:** defaults present (`email.tls`="starttls", `email.enabled`=false, `auth.webauthn.timeout`="120s", `auth.hide_local_login_ui`=false, `auth.webauthn.rp_display_name`="DIYDDNS"); env override of `DIYDDNS_EMAIL_HOST`; `ResolveWebAuthn("https://ddns.example.com")` → rpID `ddns.example.com`, origin `https://ddns.example.com`; `ResolveWebAuthn("")` with empty rp fields → error.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement:** add the struct fields (mapstructure tags for multi-word keys), the `keyDefaults` entries, and `BindEnv` coverage (every new key MUST be listed — Load has no AutomaticEnv). Add `ResolveWebAuthn` (parse `baseURL` with `net/url`). Add a `validateWebAuthnEmail(cfg)` extracted like `validateOIDC` to keep `Load` under gocyclo.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Lint + commit** (`feat(config): add auth.webauthn.*, hide_local_login_ui, and email.* sections`).

---

## Task 4: `internal/email` — SMTP subsystem

**Files:** Create `internal/email/email.go` (+ `smtp.go`, `templates.go`) + `internal/email/email_test.go`.

**Interfaces:**
- Produces: `type Mailer interface { Send(ctx context.Context, to, subject, body string) error }`; `func New(cfg config.EmailSection, log *slog.Logger) Mailer` (returns `noopMailer` when `!cfg.Enabled`, else `smtpMailer`); `func (m Mailer) Enabled() bool` via a method on the interface or a `Configured()` helper (the caller checks whether self-service recovery is available). Template helpers `RecoveryLinkBody(link string) (subject, body string)` and `AdminNotifyBody(email string) (subject, body string)` (text/template).
- Consumes: `config.EmailSection`.

- [ ] **Step 1: Failing tests:** `New(disabled)` returns a mailer whose `Send` is a no-op and `Enabled()==false`; `smtpMailer.Send` against a fake in-process SMTP listener (a `net.Listener` reading the DATA and asserting the envelope) succeeds; the SMTP password never appears in any log (assert against a captured `slog` buffer). Template bodies contain the link / email.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement:** `noopMailer{}` (logs `email.send skipped (disabled)` at debug, returns nil); `smtpMailer` using `net/smtp` — `starttls`/`implicit`/`none` per `cfg.TLS` (STARTTLS via `smtp.Client.StartTLS`, implicit via `tls.Dial` + `smtp.NewClient`, none = plain). `New` selects impl. Never include `cfg.Password` in any log line.
- [ ] **Step 4: Run — expect PASS** (`-race`).
- [ ] **Step 5: Lint + commit** (`feat(email): add net/smtp Mailer subsystem with no-op fallback`).

---

## Task 5: Service — `PasskeyService` (ceremonies, challenge cookie, credential mapping)

**Files:** Create `internal/server/service/passkey.go` + `internal/server/service/passkey_test.go`. Modify `go.mod`/`go.sum` (add `go-webauthn`; add `virtualwebauthn` as a test-only import).

**Interfaces:**
- Produces:
  - `type PasskeyService struct { … }`; `func NewPasskeyService(st *store.Store, sessions *auth.SessionManager, sealKey []byte, cfg config.WebAuthnCfg, rpID, rpOrigin string, audit AuditSink) (*PasskeyService, error)`.
  - `BeginLogin(ctx) (options []byte, sealedCookie string, err error)` — `BeginDiscoverableLogin` → JSON options + sealed `SessionData`.
  - `FinishLogin(ctx, sealedCookie string, r *http.Request, ip, ua string) (store.Session, error)` — open cookie, reject if challenge already used (used-set), `FinishDiscoverableLogin` with a handler resolving the user by `webauthn_handle`, on success `Update` credential (counter+last_used_at), reject on `CloneWarning` (audit `passkey.signcount_anomaly`), `sessions.Create`, audit `user.login.passkey`.
  - `BeginRegister(ctx, userID string) (options []byte, sealedCookie string, err error)`; `FinishRegister(ctx, userID, sealedCookie, name string, r *http.Request) (store.WebAuthnCredential, error)` — mint `webauthn_handle` if absent, `Create` credential, audit `passkey.registered`.
  - `ListCredentials(ctx, userID) ([]store.WebAuthnCredential, error)`; `Rename(ctx, userID, credID, name) error`; `Remove(ctx, userID, credID) error` (last-credential guard → `ErrLastCredential`).
  - Sentinels: `var ErrLastCredential = errors.New("service: cannot remove the last credential")`, `ErrPasskeyVerification`.
- Consumes: `store.WebAuthnCredentialRepo`, `UserRepo` handle methods, `auth.SealWithAAD`/`OpenWithAAD` (AAD const `webauthnAAD = []byte("diyddns/webauthn-v1")`), `auth.SessionManager.Create`, `config.WebAuthnCfg`.

- [ ] **Step 0 (verification spike):** `go get github.com/go-webauthn/webauthn@latest github.com/descope/virtualwebauthn@latest`; write `passkey_spike_test.go` driving one register→login round-trip through a real `PasskeyService` using `virtualwebauthn`; confirm the API compiles + passes; delete the spike (its shape becomes the harness in Step 1). Record the pinned versions in the commit message.
- [ ] **Step 1: Failing tests** (table-driven, `virtualwebauthn` authenticator): register begin returns non-empty options + a sealed cookie; register finish stores a credential and mints `webauthn_handle`; **discoverable login** finish for that credential returns a valid session and bumps `last_used_at`; a **replayed** finish (same sealed cookie + response) is rejected (used-set); a **CloneWarning** (rewind stored sign_count so the authenticator's counter looks non-increasing) → `ErrPasskeyVerification` + no session; **last-credential guard**: `Remove` of the only passkey when `OIDCSubject==""` → `ErrLastCredential`; the same `Remove` when `OIDCSubject!=""` → OK.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `passkey.go`:
  - `webauthnUser` adapter implementing `go-webauthn`'s `User` over a `store.User` + its `[]store.WebAuthnCredential` (decode each `CredentialJSON` into a `webauthn.Credential`; `WebAuthnID()` returns the user's `webauthn_handle`; `WebAuthnName()`/`WebAuthnDisplayName()` = email).
  - `NewPasskeyService` builds `webauthn.New(&webauthn.Config{RPID, RPDisplayName: cfg.RPDisplayName, RPOrigins: []string{rpOrigin}, AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationPreferred}})`.
  - Challenge cookie: `json.Marshal(*SessionData)` → `auth.SealWithAAD(sealKey, data, webauthnAAD)`; open reverses it. Single-use: a `sync.Mutex`-guarded `map[string]int64` (challenge-b64 → expiry) pruned lazily; `FinishLogin`/`FinishRegister` reject a challenge already present, else record it with the cookie TTL.
  - `FinishDiscoverableLogin` handler: `func(rawID, userHandle []byte) (webauthn.User, error)` → `Users().GetByWebAuthnHandle(userHandle)` → build `webauthnUser`; capture the resolved `store.User` in an outer var for the session mint.
  - `Remove` guard: count via `WebAuthnCredentials().ListByUser`; if removing leaves 0 AND `user.OIDCSubject==""` → `ErrLastCredential`.
- [ ] **Step 4: Run — expect PASS** (`-race`).
- [ ] **Step 5: Verify client isolation** unaffected: `go test ./cmd/diyddns-client/... -run Deps` stays green (no `webauthn` import reaches the client).
- [ ] **Step 6: Lint + commit** (`feat(service): add PasskeyService — WebAuthn ceremonies, sealed-cookie challenge, last-credential guard`; note pinned `go-webauthn`/`virtualwebauthn` versions).

---

## Task 6: Service — registration grants (invite + recovery) + bootstrap-via-passkey + self-service request

**Files:** Create `internal/server/service/grants.go` + `_test.go`. Modify `internal/server/service/bootstrap.go` (+ test) and `internal/server/service/admin.go` (+ test) — **additively** (leave existing password paths intact; they are removed in Task 10).

**Interfaces:**
- Produces `type GrantService struct { … }`; `NewGrantService(st, passkeys *PasskeyService, mailer email.Mailer, audit AuditSink, log) *GrantService`:
  - `IssueInvite(ctx, actorID, userID string) (link string, err error)` — mint grant `reason=invite`, no revoke, audit `passkey.invite_issued`.
  - `IssueRecovery(ctx, actorID, userID string) (link string, err error)` — revoke all (`DeleteAllByUser`), mint `reason=recovery`, audit `passkey.recovery_issued`.
  - `RedeemBegin(ctx, token string) (userID string, options []byte, sealedCookie string, err error)` / `RedeemFinish(ctx, token, sealedCookie string, r *http.Request, name string) error` — **verify-before-consume ordering** (see C1 note): verify the passkey (`FinishRegistration`, credential held in memory) → `Consume` the grant (atomic single-use gate) → store the credential. A store failure after Consume spends the grant (admin must re-issue) — documented, not a hang.
  - `RequestSelfServiceRecovery(ctx, email, ip string) error` — ALWAYS returns nil-shaped success; proceeds only if account exists AND has ≥1 passkey AND mailer configured: `IssueRecovery`, email the link, email admins. (I2 guard.)
- Bootstrap additions (D9/I3, **no `sql.Tx` — see C1**): `BeginClaim(ctx, token, email string) (sealedCookie string, options []byte, err error)` (validate token+email, seal email, NO consume) and `FinishClaim(ctx, sealedCookie string, r *http.Request, name string) (store.User, error)`. `FinishClaim` order: re-check `AdminExists` → build an in-memory `webauthnUser` (sealed email as name/display, a freshly-minted `webauthn_handle`, zero credentials) → `FinishRegistration` (verify the passkey, hold `*Credential` in memory, **no DB write**) → `Bootstrap.Consume` (atomic single-row gate) → `Users().Create(store.User{Email, Role:"admin"})` (**credential-less admin, NOT the password-hashing `createAdmin`** — M1) → `WebAuthnCredentials().Create` + `SetWebAuthnHandle` → audit. Verifying before Consume means an abandoned ceremony never spends the token (I3); the only residual is a credential INSERT failing after the admin INSERT (sub-ms), logged BOOTSTRAP CRITICAL with recovery = delete the admin + bootstrap rows and restart (Startup re-mints).
- Admin additions: `CreateUserInvite(ctx, actorID, email, role string) (user store.User, link string, err error)` — creates a **credential-less** user + `IssueInvite`. (I1.)

- [ ] **Step 1: Failing tests:** invite link redeems → user gains a passkey, grant consumed, second redeem fails; recovery revokes existing passkeys then link registers a fresh one; self-service request for an unknown email → no email sent, still nil; self-service for an OIDC-only account with 0 passkeys → **no email, no grant** (I2); self-service for an account with ≥1 passkey + mailer → link + admin-notify sent; bootstrap `FinishClaim` creates the admin + first passkey atomically; **abandoned bootstrap** (BeginClaim then no finish) leaves the token reusable (`Bootstrap.Get().ConsumedAt==0`); `CreateUserInvite` makes a user with no credential + returns a redeemable link.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `grants.go` + the bootstrap `BeginClaim`/`FinishClaim` methods (**no `sql.Tx`** — verify-before-consume ordering above; `st.DB().BeginTx` + pool repos would self-deadlock under `SetMaxOpenConns(1)`, C1); add `AdminService.CreateUserInvite` (creates `store.User{Email, Role, }` with no credential, then `IssueInvite`). **Token hashing:** add `auth.HashToken(token) string` (base64(sha256), suitable for the high-entropy `RandToken(32)` — argon2 is unnecessary here) + `auth.VerifyToken(hash, token) bool` (constant-time). Grant tokens and (in T10) the bootstrap token both use it — this is the token-hash primitive that survives the removal of `auth.HashPassword` in T10 (bootstrap currently hashes its token with `HashPassword`, so T10 must migrate it to `HashToken` before deleting `password.go`). Grant token = `auth.RandToken(32)`, stored as `auth.HashToken(token)`; link = `cfg.Server.BaseURL + "/register?token=" + token`.
- [ ] **Step 4: Run — expect PASS** (`-race`).
- [ ] **Step 5: Lint + commit** (`feat(service): registration grants (invite/recovery), bootstrap-via-passkey, self-service recovery`).

---

## Task 7: API — passkey + grant huma ops + ServerDeps wiring

**Files:** Create `internal/server/api/passkey.go` + `internal/server/api/passkey_test.go`. Modify `internal/server/api/api.go` (`ServerDeps` fields + a `registerPasskeyOps(apiAPI, deps)` call), `internal/server/api/admin.go` (add `POST /api/v1/admin/users/{id}/recovery`; the invite is folded into create-user in Task 10).

**Interfaces:**
- `ServerDeps` gains `Passkey *service.PasskeyService`, `Grants *service.GrantService`, `Mailer email.Mailer`, and `RPID`/`RPOrigin` (or read via `Cfg`).
- Ops (challenge cookie set/cleared via a helper `passkeyChallengeCookie(value, maxAge)` mirroring `sessionCookie`): `POST /api/v1/auth/passkey/login/begin|finish` (pre-session; finish mints the session cookie via the existing `sessionCookie`); `POST /api/v1/account/passkeys/register/begin|finish` (session[+CSRF on finish]); `GET /api/v1/account/passkeys`; `PATCH|DELETE /api/v1/account/passkeys/{id}` (session+CSRF); `POST /api/v1/auth/recovery/request` (pre-session, uniform 200); `POST /api/v1/register/begin|finish` (pre-session, token-driven redeem/bootstrap/invite); `POST /api/v1/admin/users/{id}/recovery` (session+admin+CSRF). Use `humago.Unwrap(ctx)` to recover `*http.Request` for `Finish*` (M2). Map `ErrLastCredential`→409, verification errors→401, recovery-request always→200.

- [ ] **Step 1: Failing tests** (`api_test`, EXTEND `newFullHarness` to wire `Passkey`/`Grants`/`Mailer`): guard test additions (new protected paths reject unauthenticated — extend `guard_test.go` cases); login begin returns options + a `Set-Cookie` challenge cookie; a full register→login via `virtualwebauthn` through the HTTP layer mints a session cookie; `DELETE` last passkey → 409; recovery/request → 200 uniform for both known+unknown email.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `passkey.go` (thin huma adapters over the services; DTOs marshal the library's option JSON verbatim in a `Body []byte`-equivalent — use `huma`'s raw-body pattern or a `map[string]any`). Wire `registerPasskeyOps` in `api.go`; add the admin recovery op in `admin.go`.
- [ ] **Step 4: Run — expect PASS** (`-race`).
- [ ] **Step 5: Lint + commit** (`feat(api): passkey ceremony + registration-grant + admin-recovery endpoints`).

---

## Task 8: Web UI — minimal server-rendered login / register / account pages

**Files:** Create `internal/server/webui/webui.go` (embed + handlers + stdlib middleware + shared browser-auth helper), `internal/server/webui/templates/{layout,login,register,account}.html`, `internal/server/webui/static/passkey.js`, `internal/server/webui/static/app.css`; `internal/server/webui/webui_test.go`.

**Interfaces:**
- `func New(deps Deps) http.Handler` where `Deps{Sessions *auth.SessionManager, Cfg config.Server, Log}`; a shared `authenticateBrowser(r) (store.User, store.Session, error)` helper used by BOTH the stdlib middleware here and referenced by the huma equivalent (N2 — extract the cookie→`SessionManager.Authenticate`→role check into one function). Routes: `GET /login`, `GET /register`, `GET /account` (session-guarded). The JS helper calls the Task-7 JSON ceremonies and base64url-encodes/decodes `ArrayBuffer`s.
- Consumes: `//go:embed templates/*.html static/*` `embed.FS`; `template.ParseFS` at construction.

- [ ] **Step 1: Failing tests:** `GET /login` 200 renders a passkey button; with `hide_local_login_ui=true` the passkey block is absent but the route still 200s and shows OIDC; `GET /account` without a session → 302/401; the shared `authenticateBrowser` returns the user for a valid cookie. Hidden `csrf` field present on the recovery `<form>`.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** templates (layout + 3 pages; reference the accepted mocks in `docs/designs/webui-review/mocks/` for structure — minimal, no htmx needed here), `passkey.js` (`navigator.credentials.create/get` + base64url helpers, posting to the Task-7 endpoints), `app.css` (small), and the stdlib `sessionMiddleware`/`adminMiddleware` equivalents + the shared `authenticateBrowser` helper. `New` parses templates once.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Lint + commit** (`feat(webui): minimal server-rendered passkey login/register/account pages`).

---

## Task 9: Server assembly — construct + wire everything (additive)

**Files:** Modify `internal/server/server.go` (construct `PasskeyService`/`GrantService`/`Mailer`, resolve RP ID/origin fail-closed, add to `ServerDeps`, mount `webui` routes on the mux), `internal/server/api/capabilities.go` (NO passkey flag — M5; leave unchanged), `cmd/diyddns-server/main.go` if it independently constructs services. Tests: `internal/server/server_test.go`.

- [ ] **Step 1: Failing test:** `server.Handler(cfg,…)` with a base URL wired → `GET /login` 200 and `POST /api/v1/auth/passkey/login/begin` reachable; **fail-closed**: cfg with passkey login available but no resolvable RP origin (empty base_url + empty rp_origin, not hidden) → `Handler` returns an error.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the wiring in `handler()`: `rpID, rpOrigin, err := cfg.Auth.ResolveWebAuthn(cfg.Server.BaseURL)` (fail closed unless `hide_local_login_ui` with OIDC); `mailer := email.New(cfg.Email, log)`; construct the two services; add to `api.ServerDeps`; `mux.Handle("/login"|"/register"|"/account"|"/static/", webui.New(...))`. Mount webui BEFORE `api.Build` or on distinct paths (no route collision with `/api`/`/agent`).
- [ ] **Step 4: Run — expect PASS** (`-race`, `go build ./...`).
- [ ] **Step 5: Lint + commit** (`feat(server): wire PasskeyService/GrantService/Mailer + webui routes (fail-closed RP origin)`).

---

## Task 10: Remove local password auth (the flip) + drop `password_hash`

By now passkey login works end-to-end, so removing password auth degrades nothing. This is one cohesive cross-package removal; the module must build + all tests pass at the end.

**Files:** Delete `internal/auth/password.go` + `password_test.go`. Modify: `internal/store/users.go` (drop `PasswordHash` field, `userColumns`, `scanUser`, Create/Update) + `migrations/00003_passkeys.sql` (add `ALTER TABLE users DROP COLUMN password_hash;` to Up, `ADD COLUMN password_hash TEXT` to Down); `internal/config/config.go` (remove `PasswordCfg` + `auth.password.*`; **remove env bootstrap entirely per D9 (M2): `auth.bootstrap.admin_password` AND `auth.bootstrap.admin_email`, the explicit `BindEnv` alias at `config.go:156`, and `BootstrapCfg` itself**); `internal/server/service/auth.go` (remove `Login`/`ChangePassword`/decoy; **`NewAuthService` no longer builds the decoy, so its `error` return AND `server.go:62`'s error branch go away — M3**; the file may reduce to `Logout`); `internal/server/service/admin.go` (drop `Password` from `CreateUserParams`/guards; `CreateUser`→credential-less + invite; drop password from `UpdateUserParams`/`applyRoleAndPassword`); `internal/server/service/bootstrap.go` (drop the env-email/password path + password args; **migrate the bootstrap token hash from `auth.HashPassword` to `auth.HashToken` (Task 6) BEFORE `password.go` is deleted — otherwise bootstrap's token verification breaks**; `NewBootstrapService` drops the now-unused `cfg.Auth.Bootstrap` arg); `internal/server/api/auth.go` (remove the `/auth/login` + `/auth/password` ops + password DTOs, but **RETAIN `loginMetaMiddleware`/`loginMetaFrom`/`loginRequestMeta` — T7's passkey `login/finish` reuses them for ip/ua/tls, N1**); `internal/server/api/admin.go` (`createUserInput` drops Password → returns the invite link; `newAdminUserView` `OIDCOnly`→`OIDCLinked` off `OIDCSubject`; adminErr drops `ErrOIDCNoPassword`/`ErrWeakPassword` if now unused); `internal/server/api/enroll.go` (remove `/agent/v1/enroll/credentials`); `internal/server/service/enrollment.go` (remove `EnrollCredentials`); `internal/server/server.go` + `cmd/diyddns-server/main.go` (drop `cfg.Auth.Password` args from the three constructors + the `NewAuthService` error branch).

**Test surface — the largest part of this task (I1).** The session-guarded api tests mint their cookie via `loginAndGetCSRF` (`internal/server/api/devices_test.go:139`, ~30 call sites across `admin_test.go`, `devices_manage_test.go`, `devices_test.go`) and `seedAuthUserWithPassword` (`auth_ops_test.go:145`); `server_test.go:274` uses `auth.HashPassword`+`PasswordHash`. None of these are *about* passwords. **Add a password-free session helper first** — seed a user (`Users().Create`), mint via `SessionManager.Create`, read the CSRF token off the returned `store.Session` — and replace `loginAndGetCSRF`/`seedAuthUserWithPassword` everywhere. Enumerated affected test files: `internal/server/api/{guard_test,auth_ops_test,devices_test,devices_manage_test,admin_test}.go`, `internal/server/service/{auth_test,admin_test,bootstrap_test,enrollment_test}.go`, `internal/server/server_test.go`, `internal/config/config_test.go`.

- [ ] **Step 1: Adjust/failing tests first.** Add the **password-free session helper** and migrate every `loginAndGetCSRF`/`seedAuthUserWithPassword` call site to it (I1). Update `guard_test.go` case list (remove `/auth/password`; login is now passkey). Delete password-specific tests (`auth_test.go` Login/ChangePassword, admin password-reset cases, enroll credentials tests). Add a test asserting `newAdminUserView` reports `OIDCLinked` from `OIDCSubject` and that `AdminService.CreateUser*` returns an invite link with no password. Run — expect FAIL/compile errors (drives the removal).
- [ ] **Step 2: Remove code** package-by-package in dependency order (store → auth → config → service → api → server/cmd), deleting the password paths and fixing signatures. Add the `DROP COLUMN password_hash` to migration 00003.
- [ ] **Step 3: Run the WHOLE suite** `go test ./... -race` — expect PASS (fix compile fallout until green). `go build ./...`.
- [ ] **Step 4: Verify** the decoy-timing removal is acceptable (no password enumeration surface remains) and no `PasswordHash`/`Password`/`auth.password` references linger: `grep -rn "PasswordHash\|Argon2\|auth.password\|admin_password" internal cmd` → only expected/absent.
- [ ] **Step 5: Lint + commit** (`refactor!: remove local password auth (argon2id) — passkeys + OIDC only; drop password_hash`).

---

## Task 11: Remove client `enroll --user`

**Files:** Modify `cmd/diyddns-client/enroll.go` (remove the `--user` flag, its `switch` arm, the `MarkFlagsMutuallyExclusive`/`OneRequired` lists → `oidc,code` only); delete `cmd/diyddns-client/password.go` + `password_test.go` + `resolvePassword`; `internal/client/enroll/*` (remove `EnrollCredentials` + its wire structs); `go.mod` (drop `golang.org/x/term` if now unused). Tests: update `cmd/diyddns-client/enroll_test.go` (remove --user cases, keep the 5 OIDC + code tests); **`deps_test.go` — ADD `github.com/go-webauthn/webauthn` to the forbidden-import list (M5)** so the guard actually proves passkey isolation (the current list has huma/oauth2/go-oidc/go-jose but not webauthn; the client never imports it, but the guard must assert that). The `x/term` removal is structural (no code imports it after this task).

- [ ] **Step 1: Update tests** — remove `--user` enroll tests; assert `enroll` with neither `--code` nor `--oidc` errors; keep code/oidc paths. Run — expect FAIL (compile).
- [ ] **Step 2: Remove** the `--user` arm + `resolvePassword` + `EnrollCredentials`; `go mod tidy` (drops `x/term`).
- [ ] **Step 3: Run** `go test ./... -race` (incl. the strengthened `deps_test` green — the client binary imports none of huma/oauth2/go-oidc/go-jose/**webauthn**/term) — expect PASS.
- [ ] **Step 4: Lint + commit** (`refactor!: drop client 'enroll --user' (password mode); enroll is --code/--oidc only`).

---

## Self-Review (completed by the plan author)

- **Spec coverage:** D1 clean break → T10; D2/D5/D6/D7 ceremonies → T5/T7; D3 migration/drop → T1(add)/T10(drop); D4 FK cascade → T1/T2; D8 last-credential guard → T5; D9 bootstrap-at-finish → T6; D10/D11/D15 grants+invite+self-service+I2 → T6/T7; D12 email → T4; D13 minimal UI → T8; D14 hide_local_login_ui + M4 predicate → T3/T8/T9; M1 used-challenge set → T5; M2 humago.Unwrap → T7; M3 CloneWarning → T5; M5 no capabilities flag → T9 (explicit no-op); M6 migration Down → T1; I1 invite → T6/T10; I5 DTO → T10; N1 wording → T11; N2 shared browser-auth helper → T8. Every design section maps to a task.
- **Placeholder scan:** the one library-dependent area (ceremony test harness) is pinned to a concrete verification step (T5 Step 0) with the exact go-webauthn signatures inlined — not a "TODO".
- **Type consistency:** `webauthn_handle []byte`, `credential_id []byte`, `ErrLastCredential`, `ResolveWebAuthn(baseURL) (rpID, rpOrigin, err)`, `Mailer.Send(ctx,to,subject,body)`, grant `reason ∈ {invite,recovery}` used consistently across T1–T11.

## Execution workflow

> **For Claude:** REQUIRED EXECUTION WORKFLOW:
> 1. `superpowers:using-git-worktrees` — dedicated worktree off the merged `origin/main`.
> 2. `superpowers:subagent-driven-development` — fresh subagent per task (hybrid model note: all tasks are Go/server + one JS/HTML task T8 → `sr-go-engineer` for Go tasks, `general-purpose` for T8's JS/CSS).
> 3. `superpowers:test-driven-development` — every subagent uses TDD.
> 4. `superpowers:verification-before-completion` — verify per task (`go test ./... -race` + `golangci-lint run` + client deps guard).
> 5. Per-task review (built into subagent-driven-development).
> 6. Independent whole-branch review on the full diff from branch point.
> 7. `superpowers:finishing-a-development-branch`.
>
> Skills carry their own model and effort settings. Do not override them.

**Dependencies:** T1,T2,T3,T4 independent (start in parallel). T5 needs T1. T6 needs T2,T4,T5. T7 needs T5,T6. T8 needs T7 (endpoints). T9 needs T7,T8. T10 needs T7 (passkey login live) — run after T9. T11 independent of the server chain (client-only) — any time after T10's server-side enroll-credentials removal, or standalone (coordinate the shared `/agent/v1/enroll/credentials` removal with T10).

---

## Review Provenance

- **SGE (sr-go-engineer, Fable) plan review, 2026-07-21 — verdict AMEND-BEFORE-EXECUTION; all findings folded.** Confirmed: the go-webauthn API surface + the full-Credential-JSON-blob storage refinement, the sealed-cookie + used-challenge-set single-use design, migration/FK discipline, the additive T1–T9 build-green invariant, and no webui/huma route collision.
  - **Critical:** C1 — `st.DB().BeginTx` wrapping pool-based repos self-deadlocks under `SetMaxOpenConns(1)`. Folded: T6 dropped the transaction for a **verify-before-consume** ordering (verify passkey → atomic `Bootstrap.Consume` gate → credential-less admin → store credential); design §6/D9 reconciled. (Verify-before-consume also avoids reintroducing the I3 sole-admin lockout that the SGE's suggested ordering would have.)
  - **Important:** I1 — password removal breaks ~30 shared session-minting test sites (`loginAndGetCSRF`/`seedAuthUserWithPassword`). Folded: T10 adds a password-free session helper (mint via `SessionManager.Create`) + enumerates every affected test file.
  - **Minor:** M1 (credential-less admin via `Users().Create`, not the password-hashing `createAdmin`) · M2 (T10 removes env bootstrap *entirely* — `admin_email` + alias + `BootstrapCfg`) · M3 (`NewAuthService` loses its `error` return once the decoy is gone) · M4 (migration split-across-tasks dev-DB caveat) · M5 (T11 adds `go-webauthn` to the client `deps_test` forbidden list so isolation is *asserted*). **Nit:** N1 (retain `loginMetaMiddleware` for passkey `login/finish`). All folded.
  - **Author-caught while folding:** bootstrap currently hashes its token with the `auth.HashPassword` deleted in T10 → T6 introduces `auth.HashToken`/`VerifyToken` (SHA-256, constant-time, for high-entropy tokens) used by grants + migrated-to by bootstrap in T10.
