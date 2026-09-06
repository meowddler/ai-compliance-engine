# Threat Model

STRIDE-based analysis of the AI Compliance Engine. Each threat records what is
implemented, what is not, and what an attacker would still be able to do.

Mitigations marked **PARTIAL** or **NOT MITIGATED** are stated plainly. A threat
model that lists only solved problems is marketing, not analysis.

---

## 1. System boundaries

**Trust boundaries**

| Boundary | Crosses | Trust |
|---|---|---|
| Browser → API | HTTP, JWT-authenticated | Untrusted client |
| API → PostgreSQL | Local network | Trusted, single credential |
| API → filesystem (`evidence_store/`) | Local disk | Trusted |
| API → NVIDIA inference endpoint | Public internet, API key | Untrusted response |
| Uploaded CSV → rule engine | Application memory | **Fully untrusted data** |

**Assets, in order of consequence if lost**

1. **Audit trail** — the record that findings were produced honestly. Compromise it and nothing else can be trusted.
2. **Evidence files and hashes** — the proof behind every finding.
3. **Control definitions and versions** — what "compliant" means to this organisation.
4. **Findings and posture** — the compliance conclusions themselves.
5. **Credentials** — password hashes, JWT signing key, refresh tokens, MFA secrets, encryption keys.
6. **Tenant boundary** — the guarantee that organisations cannot see each other.

**Actors**

| Actor | Capability |
|---|---|
| Anonymous | Reach the API over the network |
| Analyst | Upload evidence, read findings, update finding lifecycle |
| Auditor | Read everything, approve controls, accept risk, verify the audit chain |
| Admin | Create and delete controls, manage users, clear scan data |
| Database operator | Direct SQL access, bypassing all application logic |
| Compromised LLM / hostile prompt | Influence AI output only |

---

## 2. Spoofing

### S1 — Credential theft or brute force
**Mitigated.** Passwords are bcrypt-hashed. Failed login returns 401 with an
identical message whether the username exists or not, so accounts cannot be
enumerated. Disabled accounts are rejected on every request, not only at login.

**Residual risk.** No rate limiting on the login endpoint. An attacker with a
candidate password list can attempt them as fast as the network allows. Bcrypt's
cost factor slows this but does not stop it.
**Status: PARTIAL.**

### S2 — Forged or tampered JWT
**Mitigated.** Tokens are signed with HS256; the algorithm is constrained by an
allowlist in configuration, so `alg: none` and algorithm-confusion attacks are
rejected. `SECRET_KEY` must be at least 32 characters and the application will
not start without it. Regression tests cover forged signatures, `alg: none`,
expired tokens, and malformed input.

### S3 — Privilege escalation via token claims
**Mitigated.** Authorisation never reads the role from the token. Every request
loads the user from the database and derives capabilities from the stored role,
so editing a token's `role` claim grants nothing. Covered by test.

### S4 — Stolen refresh token
**Mitigated.** Refresh tokens are stored as hashes and rotate on every use.
Presenting a rotated token revokes the entire token family, on the reasoning
that once a token has been replayed it is unknown whether the holder is the
user or the thief.

**Residual risk.** Detection is after the fact — the attacker had a valid window
before replay was noticed.
**Status: PARTIAL.**

### S5 — Second factor bypass
**NOT MITIGATED.** MFA can be enrolled but is not enforced at login. Enforcement
requires an out-of-band recovery channel that this deployment does not have;
shipping enforcement without recovery would lock users out permanently.
**Status: NOT MITIGATED — documented in `backend/core/mfa.py`.**

---

## 3. Tampering

### T1 — Modifying the audit trail
**Mitigated.** Entries are hash-chained: each covers its own content and the
previous entry's hash. Modification, deletion, reordering, and insertion are all
detectable, and `GET /audit/verify` names the exact sequence where a chain
breaks. Proven by direct database tampering during development.

**Residual risk.** An actor with unrestricted write access can recompute the
entire chain, leaving it internally consistent. Checkpoints
(`POST /audit/checkpoint`) narrow this only if the head hash is recorded
somewhere outside the database.
**Status: PARTIAL — and stated in the endpoint's own response.**

### T2 — Altering stored evidence
**Mitigated.** Evidence is SHA-256 hashed at ingest.
`GET /evidence/{id}/verify` re-hashes the stored file and reports `TAMPERED` on
mismatch. Storage paths are encrypted at rest.

**Residual risk.** Detection is on demand, not continuous. A file altered today
is not noticed until someone verifies it.
**Status: PARTIAL.**

### T3 — Rewriting history by editing a control
**Mitigated.** Controls are immutably versioned: editing creates a new version
and the prior one is retained. Findings reference the exact version that
produced them. Controls with findings are retired rather than deleted, so
traceability survives.

### T4 — Injecting malicious data through an uploaded CSV
**Mitigated.** Uploaded values are rendered with `textContent` on every page, so
stored XSS is not achievable through the four display surfaces. Rule conditions
are data interpreted by a fixed operator dispatch; there is no `eval` and no
code path from uploaded content to execution. Regex patterns are length-bounded
and compiled defensively.

### T5 — Prompt injection through uploaded content
**Mitigated.** Untrusted values are placed only in the user turn, never merged
into system instructions, and the system prompt states that user content is data
rather than instructions. Critically, the architecture makes the outcome
irrelevant: **AI cannot set a compliance status.** The deterministic engine
assigns status before AI is invoked. Proven by a test suite that feeds injection
payloads through rule names, server IDs, and messages and asserts the verdict
does not move.

---

## 4. Repudiation

### R1 — Denying an action was taken
**Mitigated.** Every state-changing action writes a hash-chained audit entry
recording actor, action, entity, timestamp, and before/after state. Control
edits and finding lifecycle transitions capture controlled snapshots of both
states.

**Residual risk.** Reads are not audited, so "who looked at this" cannot be
answered.
**Status: PARTIAL.**

### R2 — Disputing a finding
**Mitigated.** `GET /violations/{id}/traceability` answers the eleven
auditability questions: which clause, which control version, what evidence, when
collected, what reasoning, why that status, who changed it since.

---

## 5. Information disclosure

### D1 — Cross-tenant data exposure
**Mitigated.** Every tenant-owned query filters on `organization_id`, including
the audit log, sessions, and chain verification. An automated isolation suite
proves scans, findings, controls, audit entries, and sessions do not cross the
boundary. Four isolation defects were found and fixed during review — including
scans evaluating against every tenant's rules.

**Residual risk.** Isolation is enforced in the service layer, not by database
row-level security. A future query written without the filter would leak, and
only review or a test would catch it.
**Status: PARTIAL.**

### D2 — Database or backup theft
**Mitigated.** Application-level encryption with key rotation. Evidence storage
paths, MFA secrets, and refresh tokens are stored encrypted or hashed. Ciphertext
carries the ID of the key that produced it, so rotation does not orphan
historical data.

**Residual risk.** Findings, control definitions, and audit entries are stored in
plaintext. Encryption keys live in environment variables, not a key management
service.
**Status: PARTIAL.**

### D3 — Secrets in source control
**Mitigated.** `.env` and `evidence_store/` are git-ignored; `.env.example`
documents required keys with empty values. The application refuses to start
without `SECRET_KEY` and `DATABASE_URL`, and enforces a minimum secret length.
Audit payloads redact password, token, and key fields before hashing, so an
immutable record never permanently preserves a credential.

### D4 — Error messages revealing internals
**Mitigated.** Authentication failures return one generic message. Rule
validation errors describe the rule problem, not system internals.

**Residual risk.** Some 500 responses interpolate exception text.
**Status: PARTIAL.**

### D5 — Sending sensitive data to a third-party model
**Mitigated.** Only finding metadata is sent — control name, condition, status,
message. Evidence file contents are never transmitted. Every call is recorded in
`ai_interactions` with the model, prompt version, input hash, and output.

**Residual risk.** Server identifiers and control descriptions leave the
deployment. There is no per-organisation opt-out.
**Status: PARTIAL.**

---

## 6. Denial of service

### DoS1 — Unbounded upload
**NOT MITIGATED.** No file size limit. A large upload is read entirely into
memory before parsing.
**Status: NOT MITIGATED.**

### DoS2 — Request flooding
**NOT MITIGATED.** No rate limiting on any endpoint, including login and the AI
endpoints, which are the most expensive.
**Status: NOT MITIGATED — the most significant open gap.**

### DoS3 — Catastrophic regex backtracking
**Partially mitigated.** Regex patterns are capped at 200 characters and
compilation failures are rejected at rule creation. A short pathological pattern
is still possible.
**Status: PARTIAL.**

### DoS4 — Expensive AI calls
**NOT MITIGATED.** AI endpoints are synchronous and take up to 60 seconds.
Concurrent requests hold connections for the duration.
**Status: NOT MITIGATED.**

---

## 7. Elevation of privilege

### E1 — Acting beyond an assigned role
**Mitigated.** Capability-based authorisation: endpoints check capabilities, and
roles are bundles of capabilities defined in one place. An unknown role receives
the empty set, so a typo or injected role grants nothing rather than everything.

### E2 — Author approving their own work
**Mitigated.** Separation of duties is enforced in the capability model: Admin
can create controls but not approve them; Auditor can approve but not author.
`assert_not_self_approval` rejects self-approval in code rather than leaving it
to policy. Covered by tests.

### E3 — SQL injection
**Mitigated.** All access is through the SQLAlchemy ORM with parameterised
queries. No raw SQL is constructed from user input.

### E4 — AI-driven privilege escalation
**Mitigated by architecture.** AI output is never executed and never sets a
status. Drafted controls are proposals requiring human approval, and validation
rejects anything the engine could not evaluate.

---

## 8. Summary

| Category | Mitigated | Partial | Not mitigated |
|---|---|---|---|
| Spoofing | 2 | 2 | 1 |
| Tampering | 3 | 2 | 0 |
| Repudiation | 1 | 1 | 0 |
| Information disclosure | 1 | 4 | 0 |
| Denial of service | 0 | 1 | 3 |
| Elevation of privilege | 4 | 0 | 0 |

**The largest open risk is denial of service.** There is no rate limiting
anywhere, no upload size limit, and AI endpoints are synchronous and expensive.
On a network-exposed deployment these are the first things an attacker would
reach for, and the first things that should be built.

**The second is that tenant isolation depends on discipline** rather than being
enforced by the database. Every current query is correct and tested, but nothing
prevents the next one from being wrong.

---

*Reviewed as part of Phase 6. Revisit when authentication, tenancy, or the AI
integration changes.*