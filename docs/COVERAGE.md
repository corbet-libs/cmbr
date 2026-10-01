# Coverage

CI resolves one fresh Cargo.lock and uses that snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. Only the four disabled PIN continuation lines described below are
proposed for exclusion. Only test harness files (`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.

The coverage job exports raw JSON and LCOV from the same actual test execution.
The gate requires every emitted production DA line and BRDA branch to have a
nonzero counter, at 100% for both metrics. It cross-checks file inventories,
summaries and emitted branch locations against the companion JSON. Missing,
duplicate, empty or malformed evidence cannot pass. Raw JSON totals remain
as diagnostic evidence for generic instantiations; source coverage does not
claim every generic instantiation is covered. Both artifacts are retained on
failure. No production source exclusions are currently approved; the proposal below
requires independent review.

The registration facade delegates receipt community/member validation to
`cnrl::Enrol::apply(Event::PasskeyRegistered)`, which checks both against the
immutable enrolment row before committing. Its redundant member-only check has
been removed; no receipt can bypass the owning boundary.

Both detached membership mutations use one private completion helper. Its real
Tokio task-unwind test and the actual cancelled-reservation integration test
exercise failure mapping and completion after the request is dropped.

The encoded PIN-change verifier currently always refuses: `cgts::pins::SpentChange`
has no public constructor, and `verify_encoded_pin_change` returns
`ExtensionsUnavailable` after validating the canonical change binding. The
success continuation is not claimed tested or enabled. A real owner acceptance
capability remains necessary before this workflow can complete.

## Proposed disabled PIN continuation exception

The four lines after the encoded spend verifier are unreachable in the current
resolved owner graph. They are not an enabled PIN-change implementation. The
[exact cgts verifier](https://github.com/corbet-libs/cgts/blob/de4164835f4eb1fbd90f06d40cd7a4632a02af4b/src/pins.rs)
validates the canonical binding and then unconditionally returns
`ExtensionsUnavailable`; its `SpentChange` is sealed, non-deserializable and has
no public constructor. Neither arbitrary wire bytes nor dependency feature
unification can produce a witness. Its `PinSpendVerifier` also always refuses.

The refusal and invalid-binding paths execute in real Membership tests. The
unchanged native restart test confirms no PIN mutation for arbitrary, purported
signed and replayed bytes; the revision-overflow vector reaches binding refusal.
No fake spend or accepting adapter substitutes for the accounting owner.

Only the four source counters for the inaccessible `Pins::change` continuation
are proposed for exclusion. Every line/branch inventory is still reconciled
across the same-execution JSON, LCOV and annotated reports. Entries bind the
complete membership implementation and its actual integration tests, plus the
exact unique cgts version/full Git source in the resolved Cargo.lock. The proof
uses only that owner: its unconditional refusal cannot become successful through
a transitive dependency. A moved, changed, missing or executed line, or changed
supporting source/owner revision, fails the gate and requires renewed review.
Unrelated dependency updates still run the complete real test/coverage suite. No branch
or whole function is excluded. The owner source SHA-256 is `3d45c3322a344db24b3dae20de2197cf1b2c4c6b6db7c86f90270c0e8f1cad87`.

Independent review is required. This exception does not satisfy the blocked
positive PIN-change workflow: when the owner releases a real spend capability,
remove the exception and execute actual accepted-spend, replay and crash tests.
