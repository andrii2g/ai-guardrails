# AIGuardrails Contracts

This document defines the non-negotiable MVP contracts for AIGuardrails. If implementation behavior differs from this file, the implementation is wrong.

Related documents:

- [Overview](./overview.md)
- [CLI](./cli.md)
- [Detailed design in PLAN.md](../PLAN.md)

## Rule Match Inputs

Only the following paths are valid in policy rule `match` conditions:

```text
action
subject.type
subject.id
resource.type
resource.id
trusted.<key>
trusted.<key>.value
trusted.<key>.issuer
trusted.<key>.version
```

The following are forbidden in rule `match` conditions in the MVP:

```text
request.attributes.<key>
subject.attributes.<key>
resource.attributes.<key>
context.<key>
attributes.<key>
```

Policy loading must fail if any forbidden rule-match path appears.

## Trusted Signal Contract

Trusted signals are the only safety-critical evidence source in the MVP.

Trusted signal key grammar:

```text
^[A-Za-z][A-Za-z0-9_-]{0,63}$
```

Keys must not contain dots.

Each trusted signal carries:

- `Value`
- `Issuer`
- optional `Version`
- `IssuedAtUtc`

Trusted signals must come from trusted server-side components. They must not be copied directly from user input, model output, browser payloads, or unverified upstream services.

## Freshness and Replay Protection

Freshness is enforced only for decision-relevant trusted signals.

A trusted signal is decision-relevant when:

1. a rule references `trusted.<key>`, `trusted.<key>.value`, `trusted.<key>.issuer`, or `trusted.<key>.version`
2. all non-trusted conditions in that same rule match the request

Freshness rules:

- `defaultMaxAgeSeconds` must be greater than `0`
- per-key max ages must be greater than `0`
- the engine must use UTC time
- the engine must use an injectable clock for deterministic tests
- stale decision-relevant trusted signals produce `InvalidRequest`
- decision-relevant trusted signals more than 60 seconds in the future produce `InvalidRequest`
- stale unrelated trusted signals must not invalidate unrelated requests
- audit-only inclusion does not make a trusted signal decision-relevant

## Evaluation Statuses

The engine must return one of these statuses:

```text
Evaluated
InvalidRequest
AuditWriteFailed
RuntimeError
```

Semantics:

- `Evaluated`: the engine produced a decision and enforcement may proceed according to that decision
- `InvalidRequest`: input or decision-relevant trusted evidence is invalid
- `AuditWriteFailed`: the decision was computed, but fail-closed audit handling prevents execution
- `RuntimeError`: unexpected operational failure during evaluation

`InvalidRequest`, `AuditWriteFailed`, and `RuntimeError` must never be mapped into `Deny`.

## ExecutionAllowed Contract

The result exposes:

```text
ExecutionAllowed == true only when:
status == Evaluated and decision == Allow
```

This is the only in-process success predicate for execution.

If `status == AuditWriteFailed`, execution is not allowed even if the embedded computed decision is `Allow`.

## Audit Failure Contract

If audit is enabled and an audit sink is configured:

- the engine must generate the decision
- the engine must generate the audit event
- the engine must attempt to write the audit event

Fail-closed mode:

- return `AuditWriteFailed`
- keep the computed decision
- keep the generated audit event
- include error details
- callers must not execute the operation

Best-effort mode:

- return `Evaluated`
- keep the computed decision
- keep the generated audit event
- add a diagnostic entry describing the audit write failure

MVP default is fail-closed.

## Runtime Error Boundary

The engine must return `RuntimeError` for unexpected operational failures during evaluation, including failures in:

- match path resolution
- wildcard matching
- rule evaluation
- precedence calculation
- reason generation
- audit event construction
- audit snapshot construction
- trusted signal relevance detection
- trusted signal freshness evaluation
- clock access

The engine may throw only for programmer or construction errors, such as:

- null policy passed to the engine constructor
- invalid policy object passed directly without the loader
- invalid null dependency wiring
- misuse of internal APIs by library code

## Audit Evidence Contract

Audit events must record the exact trusted evidence used by winning matched rules.

For each trusted match that contributed to a winning rule, the audit event must capture:

- `RuleId`
- `Path`
- `SignalKey`
- `Field`
- `Expected`
- `Actual`
- `SignalValue`
- `SignalIssuer`
- `SignalVersion` when present
- `SignalIssuedAtUtc`

Trusted evidence not referenced by winning matched rules must not be logged in `MatchedTrustedEvidence`.

## Audit Snapshot Contract

Audit snapshots are allowlist-first:

- if `audit.includeFields` is empty, the request snapshot is empty
- only included fields may appear
- redaction is applied after selection
- redaction must not add new fields

Untrusted fields may appear in audit snapshots, but only through audit include/redact configuration. They remain invalid for rule matching.
