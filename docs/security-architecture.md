# Security Architecture

How the AI Compliance Engine defends itself, and why each mechanism was chosen.
Written to be read by someone deciding whether to trust the system's output.

---

## The governing principle

**Fail closed.** When the system cannot do something safely, it stops and says
so rather than guessing. This is not a slogan — it is implemented at every
layer:

| Situation | Behaviour |
|---|---|
| `SECRET_KEY` or `DATABASE_URL` missing | The application refuses to start |
| A rule cannot be evaluated | `INSUFFICIENT_EVIDENCE`, never `PASS` |
| A data cell is blank | `INSUFFICIENT_EVIDENCE`, never `PASS` |
| Evidence is older than its validity window | The control degrades, never silently passes |
| Nothing has been evaluated | Posture is "cannot be computed", not 100% |
| A scan fails partway | Nothing is saved |
| A role is unrecognised | No capabilities, rather than all of them |
| An AI response is malformed | Rejected whole, never partially accepted |

The pattern throughout is that *unknown* is a distinct outcome from *fine*. A
compliance tool that conflates them will report a system as safe because it
never actually looked.

---

## 1. Authentication

**Passwords** are hashed with bcrypt. Verification returns `False` on a
malformed hash rather than raising, so a corrupt record reads as a wrong
password rather than a 500 that confirms the account exists.

**Access tokens** are JWTs signed with HS256. They are short-lived and stateless
— revoking one is impossible, so instead they expire quickly. The algorithm is
constrained by an allowlist in configuration; reading it unrestricted from the
environment would allow `alg: none`, which disables verification entirely.

**Refresh tokens** are long-lived and therefore stored server-side, which is
what makes revocation possible at all. Two properties matter:

- Only a **hash** is stored. A database read must not yield a usable credential.
- Tokens **rotate on use**. If a rotated token is presented again, either it was
  stolen or replayed — and since it is unknowable which party holds the newer
  token, the **entire family is revoked** rather than the single token.

**Failed logins** return 401 with an identical message regardless of whether the
username exists. Distinguishing the two would let an attacker enumerate accounts.

**MFA** is enrolable but **not enforced at login**. TOTP secrets are stored
encrypted and recovery codes are bcrypt-hashed and single-use. Enforcement is
absent because it requires an out-of-band recovery channel this deployment does
not have; shipping it without recovery would lock users out permanently.

---

## 2. Authorisation

**Capabilities, not role names.** Endpoints require a capability
(`controls.create`, `audit.verify`); roles are bundles of capabilities defined
in one place. A typo in a role string produces the empty capability set, so it
denies rather than grants.

**Resolved from the database on every request.** The token carries a username;
the role and organisation are loaded fresh. A privilege change takes effect
immediately, and editing a token's `role` claim grants nothing. This is verified
by a test that signs a valid token claiming Admin for an Analyst account and
asserts the request is refused.

**Separation of duties** is enforced in the capability model rather than left to
process documentation:

| Role | Can create controls | Can approve controls | Can accept risk |
|---|---|---|---|
| Admin | Yes | **No** | **No** |
| Auditor | **No** | Yes | Yes |
| Analyst | No | No | No |

An administrator who could both author and approve a control would make
independent review impossible. `assert_not_self_approval` additionally rejects
any case where author and approver are the same person.

---

## 3. Tenant isolation

Every tenant-owned table carries `organization_id`, and every query filters on
it — including the audit log, session list, and chain verification, which are
easy to overlook and the most sensitive to leak.

An automated isolation suite proves that one organisation cannot read another's
scans, findings, controls, audit entries, or sessions.

**Honest limitation:** isolation is enforced in the service layer, not by
database row-level security. Four isolation defects were found during review —
including scans evaluating against every tenant's rules — which demonstrates
that this design depends on discipline. Row-level security would make the
guarantee structural rather than behavioural.

---

## 4. Data integrity

### Evidence
Uploaded files are stored, never discarded, and SHA-256 hashed at ingest. The
hash covers exactly the bytes received. `GET /evidence/{id}/verify` re-hashes the
stored file and reports `TAMPERED` on mismatch — demonstrated during development
by modifying a stored file and watching the check fail.

### Controls
Immutably versioned. Editing creates a new version; the previous one is retained
and marked non-current. A control that has produced findings is **retired rather
than deleted**, because deleting it would orphan every finding that cites it and
destroy the traceability the audit trail depends on.

### Findings
Each links to the exact evidence file and the exact control version that
produced it, so any finding can be re-derived.

### Audit trail
Hash-chained: each entry's hash covers its own content plus the previous entry's
hash. Modification, deletion, reordering, and insertion all break every
subsequent hash, and verification names the exact sequence where the break
occurs.

The **canonical serialization** is the foundation of this. If the same logical
event could serialize two different ways, verification would fail on differences
that do not matter and the chain would be worthless. So keys are sorted,
separators fixed, unicode preserved, timestamps normalised to UTC in one format,
and floats formatted with `repr` for platform stability. The format is versioned,
because changing it would invalidate every existing hash.

**Stated limitation:** an actor with unrestricted database write access can
recompute the whole chain. Hash chaining detects ad-hoc tampering, not a
wholesale rewrite. Checkpoints narrow this only when the head hash is recorded
outside the database — and the verification endpoint says so in its own response
rather than implying more protection than exists.

---

## 5. Encryption at rest

Application-level, applied before values reach the database, so a dump or backup
yields ciphertext.

**Key rotation is the hard part**, and is handled by tagging each ciphertext with
the ID of the key that produced it:

```
<key_id>:<ciphertext>
```

New writes use the active key; reads use whichever key the value was written
with. Rotation therefore means changing which key is active — historical data
stays readable, and a partial rotation is recoverable rather than destructive.
Fernet authenticates its payload, so a modified ciphertext is rejected instead
of decrypting to garbage.

Encrypted today: evidence storage paths, MFA secrets. Hashed: passwords, refresh
tokens, recovery codes.

**Not encrypted:** findings, control definitions, audit entries. Keys live in
environment variables rather than a key management service.

---

## 6. Input handling

**Uploaded data is treated as hostile throughout.**

Rule conditions are *data*, evaluated by a fixed operator dispatch. There is no
`eval`, and no path from uploaded content to code execution. Regex patterns are
length-bounded and compiled defensively; condition trees are depth-limited.

Validation happens **at the boundary**, and the schema validator imports its
operator set from the rule engine rather than restating it — two copies would
drift, and a rule that passes validation then fails during a scan is worse than
one rejected at the door.

Every display surface renders uploaded values with `textContent`. Stored XSS was
present in four places and fixed in all four; the lesson recorded here is that
stored XSS must be fixed at *every* sink, not where it was first noticed.

---

## 7. The AI trust boundary

**AI proposes and explains. Deterministic rules decide.**

This is architectural, not a policy statement. The rule engine assigns a status
before AI is ever invoked, and no code path lets model output alter one. The
worst outcome of a fully compromised model is a bad explanation.

Defences, in order of reliability:

1. **Architecture** — AI cannot set a status. This holds even if everything else fails.
2. **Separation** — untrusted content goes in the user turn, never merged into system instructions.
3. **Instruction** — the system prompt states that user content is data, not instructions.
4. **Validation** — structured output is schema-checked; malformed proposals are rejected whole.
5. **Human approval** — drafted controls are proposals until a person approves them.

A prompt-injection suite feeds payloads through rule names, server IDs, and
messages, and asserts the compliance verdict does not move.

Every call is recorded in `ai_interactions`: model, prompt version, input hash,
output, latency, tokens, requester. Prompts are versioned, so a bad explanation
can be traced to whether the model or the prompt was at fault.

---

## 8. Auditability

`GET /violations/{id}/traceability` answers the eleven auditability questions for
any finding: which clause, which control version, what evidence, when collected,
which evaluator, what reasoning, what confidence, why that status, who changed
it, which framework version, and whether the trail is tamper-evident.

Every state-changing action writes an audit entry with actor, action, entity,
timestamp, and controlled before/after snapshots. Snapshots are deliberately
explicit rather than serialising whole ORM objects — an audit record is
permanent, so what enters it should be a decision, not an accident of which
columns exist.

---

## 9. Data governance

Retention policies are stored data with an owner and an audit history, not a
cron job, because an auditor asks what the policy *is* and when it changed.

Two rules govern deletion, in precedence order:

1. **A legal hold always wins.** A record under hold survives its retention
   window, because a legal obligation outranks a housekeeping rule.
2. **Audit history is never deletable by retention.** A system that can quietly
   age out its own audit trail cannot be audited.

Evaluation is **read-only**. It reports what would be eligible and what blocks
it; deletion is a separate, explicitly authorised act.

---

## 10. Supply chain and CI

Every push runs: the full test suite against a real PostgreSQL, lint scoped to
defect-catching rules, `bandit` static analysis failing on high-severity
findings, and `pip-audit` for known vulnerabilities.

The lint configuration is deliberately narrow. A linter reporting hundreds of
style findings on working code gets ignored, and an ignored linter is worse than
none.

Known-vulnerable dependencies with no available fix are recorded in
`docs/accepted-risks.md` with the reason the exposure is limited and what would
change the decision — not silently suppressed.

CI has already earned its place: it caught a call to an undefined function that
would have broken every scan upload, which the test suite missed because no test
uploaded a file through the API.

---

## 11. What is not defended

Repeated here because it belongs in the same document as the defences:

- **No rate limiting anywhere.** Login and the AI endpoints are both unprotected. This is the largest open gap.
- **No upload size limit.** Files are read entirely into memory.
- **MFA is not enforced at login.**
- **AI endpoints are synchronous** and hold a connection for up to a minute.
- **Tenant isolation is behavioural**, not enforced by the database.
- **No penetration test** has been performed.
- **Read access is not audited** — "who viewed this" cannot be answered.

See `docs/threat-model.md` for the full analysis.