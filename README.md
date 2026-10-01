# cmbr

Community membership facade under `cvld → cmty`, composing the finished Rust
leaves. Native server library, FSL-1.1-ALv2; interfaces are experimental.

`Membership` exposes first passkey registration, account-first login, authenticated
resume/lobby, handle reservation/lookup, register lookup, admission/renewal, lapse, pins and authorized
pin changes, passkey revocation, lost-key release, self-ban, and bounded maintenance.
It delegates execution to `ckyh`, `crgs`, `cnrl`, `cpns`, `clbs`, `crbk` and `cgrd`.
See [the implemented contract](docs/CONTRACT.md) before embedding it.

## Integration

The service opens one `crlt::Db` per community, includes `SCHEMAS` in its complete
numbered migration history, and constructs `Membership::new` inside its existing
multithreaded Tokio runtime. All leaf stores use that database and the coordinator's
fixed community. `LibsqlStorage` is the persistent coordinator; `MemoryStorage`
is a real CAS implementation for tests. ckyh's synchronous operations run on
Tokio blocking workers; no request creates a runtime or connection pool.

The caller verifies the global presentation and binds a community-local UUID to
its canonical text pseudonym before `begin_registration`. cnrl enforces unique
UUID and pseudonym bindings; crgs receives the exact pseudonym's UTF-8 bytes.
Never reuse a global identity or an identity from another community. Keep pending
WebAuthn state in a bounded, client-bound server session and consume it once.
Login always returns to the lobby; no membership state alone grants forum access.

Provide authenticated current rulebook snapshots and verified gate metadata to
`lobby`, `admit` and `lapse`. Provide the policy's reserved-name list to
`reserve_handle`; cgrd performs PRECIS/UTS #39/profanity validation. The service
also authorizes schema fields before initial pinning. It never sends field values
or salts here. Current lease, session/device authorization, per-action legal veto,
throttling, snapshot freshness and credential issuance remain with the outer door.

## Coordination and recovery

cmbr uses per-member queues, with no community-wide or durable Busy lock.
Reservation and admission complete in owned tasks after caller cancellation.
Read-only and unauthenticated lookups take no write lock. Leaves retain their
atomic revision and uniqueness checks. Failed cross-leaf operations require a
fresh authorized retry; no recovery path fabricates a positive decision.

Admission accepts cplc verified settings and cgts checked witnesses. cplc owns
the decision and reads cmbr's stored day probation and bounded lease to issue.
The pure lobby returns no-return expiry and second-device/synced-passkey warnings.
Revoked-passkey sessions stop immediately; a durable outbox carries security
changes to cplc before further credentials can be signed.


## Dependency survey

Surveyed crates.io and GitHub on 2026-09-30; leaf READMEs and implemented contracts
were read before integration. Exact revisions are in `Cargo.toml`.

| Candidate | Choice and reason |
|---|---|
| [ckyh](https://github.com/corbet-foss/ckyh), [webauthn-rs 0.5.5](https://crates.io/crates/webauthn-rs/0.5.5) | Use ckyh's established UV-required verification, counters and libSQL adapter. No second WebAuthn implementation. cnrl's ckyh pin was advanced upstream to share these exact types. |
| [crgs](https://github.com/corbet-foss/crgs), [cnrl](https://github.com/corbet-foss/cnrl) | Use register/lease rules and the existing resumable state machine. This facade owns only orchestration and identity binding. |
| [statig 0.4.1](https://crates.io/crates/statig), [smlang](https://github.com/korken89/smlang-rs) | Maintained state-machine candidates; not added because cnrl already executes the required lifecycle. |
| [cpns](https://github.com/corbet-foss/cpns) | Reuse fingerprint types, insert-only pins and spent-token CAS. No hashing or token protocol in cmbr. |
| [clbs](https://github.com/corbet-foss/clbs), [crbk](https://github.com/corbet-foss/crbk), [cgrd](https://github.com/corbet-foss/cgrd) | Reuse verified restrictions, policy evaluation, and validated Unicode handle skeletons. No substitute legal verifier, rule engine or handle checker. |
| [crlt](https://github.com/corbet-foss/crlt), [official libsql](https://github.com/tursodatabase/libsql) | crlt main is ready. All persistence goes through its scoped immediate transactions and mandatory query-plan checks; no direct driver or ORM. |
| [cblc](https://github.com/corbet-libs/cblc/blob/main/docs/EXTENSIONS.md) | Its extension contract leaves cpns authorization consumption and complete change-proof integration open. cgts supplies a sealed fail-closed adapter; cmbr never accepts a caller-supplied spend verifier. |

The selected leaves use LGPL-3.0-only with their linking exception. WebAuthn is
MPL-2.0. Serde/serde_json, Tokio, chrono and thiserror provide encoding, scheduling,
calendar validation and fixed errors (MIT/Apache-2.0). Test-only software
authenticators, tempfile and ed25519-dalek generate real ceremonies and signatures.
No cryptographic primitive or leaf execution logic is reimplemented.

## Verification and remaining integration

GitHub Actions runs stable Rust formatting, strict all-target Clippy and real
libSQL round trips. Tests exercise WebAuthn, state/resume, policy, pins, confirmed
self-ban, isolation, failures, crashes, recovery and indexes. Coordination also
runs against its memory implementation. External self-ban verifier
fixtures test the adapter contract, not production cblc proofs or device protocols.
The development gate exists only in tests, with no production feature or provider.

The optional Turso test skips unless **both** `TURSO_URL` and `TURSO_TOKEN` are
nonempty. Supply only a disposable test database: migrations and synthetic records
are written. Credentials are never configured in source or public CI. The CI
artifact retains the resolved lockfile; builds run only on GitHub Actions.
Never publish this crate to a registry.

Open: proven cblc extension circuit and intent-bound self-ban verifier adapters; approved
additional-device registration and session invalidation; discoverable login in
ckyh; full private balance extension proofs before activating change-token gates.
No raw gate data, login dates, device names or request logs are stored. Dependency
SQL/HTTP tracing and proxy body logging must stay disabled in the service.

## License

Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
