# Implemented cmbr contract

cmbr is the FSL-1.1-ALv2 membership facade under cvld v0.4's community facade,
cmnt. It composes crgs (register), cpky (passkeys), cnrl (enrolment), cpns (pins),
with clbs restrictions, crbk decisions and cgrd handle validation. Rust native
server code, current stable compiler. No own cryptography, leaf state machine,
Unicode normalization, register policy, passkey verifier or pin-change executor.

## Binding lifecycle and API

Started → passkey registered → handle reserved → gates in progress → admitted
⇄ lapsed → released. Pending registrations expire at cnrl's fixed coarse deadline
and free reservations. Terminal rows cannot be revived. There is no recovery of
lost identity. Handles remain under crgs's committed coarse lease/release policy,
normally 24 months after the lease; self-ban does not immediately free them.

- `begin_registration` / `finish_registration`: first credential only; call cpky,
  commit its verification material and apply the actual receipt to cnrl. An
  existing identity never accepts a new credential through unauthenticated retry.
  A later lookup reconciles a committed passkey whose enrolment receipt was lost.
- `begin_login` / `finish_login`: account-first WebAuthn, UV required, monotonic
  counter/revocation rules delegated to cpky. Pending states are opaque, consumed
  once, instance-bound and ephemeral. Success returns authentication and lobby
  state, with no login timestamp or implicit lease extension.
- `enrolment_state` is trusted orchestration. `resume` requires cpky's opaque
  authentication and enforces its community/user binding. All passkeys for that
  UUID resolve to one stable pseudonym in cnrl.
- `reserve_handle` validates with cgrd using the current trusted reserved list,
  reserves crgs's unique skeleton until exactly cnrl's deadline, then records
  that receipt. `handle` returns that canonical reservation or the active handle;
  `member` returns the current register record for lease/role checks. Admission
  reads the stored handle directly, so callers cannot substitute its skeleton.
  No independent or sliding reservation lifetime exists.
- `lobby` calls cnrl/crbk with verified proof metadata and current signed-policy
  content; returns current state and missing requirements, storing neither gates
  nor the verdict. `admit` reevaluates inside serialization, requires a positive
  decision and legal clearance, commits crgs admission/lease renewal, and sends
  the receipt to cnrl. Initial role is Member; this API cannot assign admin/root.
  `lapse` requires a fresh negative rulebook decision. Re-admission is explicit.
- `pin`, `get_pin`, `change_pin` call cpns. Only fingerprint and revision are
  stored; no values, salts, token evidence or history. Changes require a verified
  completed spend bound to community, member, field, old digest/revision and new
  digest. cpns's revision CAS protects replay; errors never imply a refund.
- `revoke_passkey` revokes an owned credential in cpky. Last-key revocation and
  `release` consume cnrl's lost-key event. Release refuses with live credentials.
  Physical loss detection and authorization to revoke belong to the service.
- `self_ban` binds the signed order to the authenticated pseudonym and calls clbs's
  fresh intent-bound verifier before applying its immutable restriction. A normal
  authentication result is not self-ban evidence. Exact retries still verify.
- `maintain` bounds pending expiry, owner-safe reservation cancellation and crgs
  retention release, serialized against admission. Released register records are
  consumed on subsequent state/resume. Schedule maintenance without user activity.

## Authority and identity

The API is trusted in-process composition, never an untrusted RPC surface. The
service verifies global presentations, allocates community-local nonnil UUIDs,
chooses canonical pseudonym text, and protects registration sessions. cnrl's
unique constraints prevent one user rebinding or two users claiming one pseudonym.
crgs uses exactly that text's UTF-8 bytes; no global identifier is stored or derived.

All leaf stores are constructed privately from the same Db and fixed coordinator
scope. Deploy one database per community. The service must also ensure that the
coordinator refers to that same database; supplying a separate coordinator for
each instance defeats serialization. Direct leaf writes are outside the contract.
The outer service must preserve signature/freshness checks on policy and gate
inputs, reserved names, schema-field authorization, registration throttling and
session/device approval. Authentication is an in-process receipt, not an expiring
bearer token; cpky cannot invalidate previously returned receipts. Session renewal
and immediate invalidation on device removal belong to cmnt/cvld.

clbs's configured membership action is checked before live membership operations.
Its permanent restrictions release the lifecycle and temporary restrictions lapse
it. Errors fail closed. Outer cgts still checks the exact requested action before
every service action. External legal writers must coordinate with the service if
an order must cancel a concurrent action; clbs checks are point-in-time reads.
Self-ban retries may enter after a veto so they can verify/reconcile the same order.
An enrolment state is never an access credential; current lease, gates, policy and
revocation must be checked before the outer service signs one.

## Transaction coordination

`Storage` defines fixed community, load and strict atomic compare/exchange.
`MemoryStorage` shares a mutex; `LibsqlStorage` uses crlt immediate transactions.
`cmbr_coordination` has a primary key `(community_id, slot)` and a single fixed
slot per community. Exact retries of CAS fail, ensuring only one caller owns it.
A monotonically increasing generation prevents ABA. Indexed queries select/update
that exact slot; literal insertion scans nothing. crlt enforces all query plans.

Every operation first commits an occupied slot. It holds no timestamp, timer,
request ID or idle member identity. Reservation/admission operations replace it
with a minimal intent and user reference before touching crgs. Admission intents
also retain the requested coarse lease. Recovery loads cnrl's validated current
record instead of persisting or trusting a duplicate lifecycle snapshot. This
is current unfinished work, removed on completion, not a request/event ledger.
It prevents cnrl expiry or release from racing a committed register operation
whose receipt has not reached cnrl. Known register refusals clear their intent;
ambiguous outcomes and cancellation keep the slot occupied. A crashed single-leaf
operation can be reconciled from that leaf's current state. cpky worker execution
may outlive cancellation, so stopping only its calling task is insufficient.

There is no shared SQL transaction across leaves and no automatic lock timeout.
`recover_after_quiescence` is a trusted startup/admin operation: stop every writer
and outstanding blocking worker for that community, establish one external recovery
leader, then call it before serving traffic. Calling it while a writer is live or
running multiple recoverers violates the contract. It never spends tokens, replays
WebAuthn responses or accepts new admission from a stale policy decision.

Reservation recovery replays the exact idempotent reservation while its deadline
is live, or cancels that owner's reservation and expires cnrl after the deadline.
Admission recovery reads crgs: absence or a lease below the requested target
means no completed admission/renewal; a matching record supplies the receipt. The intent proves that the facade already obtained
a positive decision. For an interrupted pending admission it completes cnrl at
`min(now, pending_deadline - 1, lease_month_start)` so expiry cannot override a
committed admission, including recovery after the coarse lease has elapsed.
For renewal there is no pending cutoff; the lease bound still applies.
This logical reconciliation point is not stored as a timestamp and grants no
current access. Current policy/legal/lease evaluation is required afterwards.
A failed reconciliation leaves the intent intact and fails closed.

A remote write error can have an uncertain outcome. Do not clear a busy marker on
elapsed time, refund a spend, reset a pin revision, erase tombstones or restore an
old database while credentials/spends survive. Such operations require external
coordinated invalidation. Higher concurrency and automatic fenced recovery await
shared transaction support in the leaves.

## Persistence, privacy and verification

The composition root adds `SCHEMAS` to its complete migration list and supplies
crlt credentials. No library reads environment credentials. All tables retain
community keys and all queries are index-backed, including shared-DB isolation
tests. Migrations have no activity timestamps. Persistent state is current
membership, identity binding, passkey verification data, handle/lease, pins, legal
metadata owned by clbs, and current coordination work. No login dates, request
logs, raw gate data, profile values, salts or member event history are recorded.
Errors are fixed categories without leaf sources or sensitive context. Keep
upstream tracing and service request/body logging disabled.

Tests use actual libSQL files, WebAuthn software authenticators, real signed clbs
fixtures, real cnrl/crgs/cpns logic, CAS races and crash/restart reconciliation.
Memory coordination exercises the same contract. A development gate is test-only.
External verifier fixtures are not production change-token or legal protocols.
Turso tests run only with both environment variables set, against disposable data;
public CI receives neither. All Cargo checks run on GitHub Actions; no registry
publication. Production cblc-to-cpns spend binding and the approved additional-device
and fresh self-ban protocols remain explicit integration boundaries.

## Door queries

`is_handle_available` applies the existing guard and register reservation/lease
rules without exposing an owner. Throttle it before calling. `session_is_active`
revalidates the exact credential behind an opaque authentication receipt; revoking
that credential invalidates its sessions even if another passkey remains active.
Both operations use the existing facade coordinator and fixed community scope.
