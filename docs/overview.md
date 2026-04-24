# AIGuardrails Overview

This document is the high-level specification for AIGuardrails. It is intended to be easier to read than [PLAN.md](../PLAN.md), while preserving the MVP behavior that must not drift during implementation.

Related documents:

- [Contracts](./contracts.md)
- [CLI](./cli.md)

## Purpose

AIGuardrails is a deterministic policy engine that evaluates whether an AI-driven or service-driven action may execute.

The engine evaluates:

```text
Subject + Action + Resource + Fresh Trusted Signals + Policy -> Evaluation Result + Audit Event
```

The core library does not call AI models. It evaluates structured inputs against deterministic policies and returns a decision or a typed failure.

## Scope

The MVP covers:

- a reusable core guardrails engine
- a policy loader and validator
- a CLI for request validation and policy evaluation
- mandatory audit generation when enabled
- strict trust-boundary enforcement
- replay protection for decision-relevant trusted signals

The MVP does not include:

- policy distribution or remote policy management
- ASP.NET middleware
- MCP integration
- regex or custom operators
- permissive matching on untrusted request attributes or context

## System Components

The repository is expected to contain:

```text
ai-guardrails/
  src/
    AIGuardrails.Core/
    AIGuardrails.Cli/
  policies/
    default.policy.yaml
  examples/
    simple-cli/
  tests/
    AIGuardrails.Tests/
  AIGuardrails.slnx
  README.md
```

High-level responsibilities:

- `AIGuardrails.Core`: request validation, policy loading, rule evaluation, decision generation, audit event generation
- `AIGuardrails.Cli`: file-based policy/request loading, status-to-exit-code mapping, JSON output envelope
- `policies/`: declarative policy definitions
- `tests/`: acceptance and contract verification for engine, loader, audit, and CLI behavior

## Core Flow

At a high level, the engine processes a request in this order:

1. Validate request structure.
2. Identify decision-relevant trusted signals.
3. Validate freshness of those trusted signals.
4. Evaluate rules using only MVP-approved match fields.
5. Apply precedence: `deny > review > allow`.
6. Generate a deterministic result and reason.
7. Generate an audit event when audit is enabled.
8. Write the audit event if an audit sink is configured.
9. Return a typed evaluation result.

The output is not just a policy decision. It is an evaluation result with explicit status, so invalid requests, audit failures, and runtime failures cannot be confused with `Deny`.

## Trust Boundary

The most important MVP design rule is that untrusted data cannot drive policy rule matching.

Untrusted data includes:

- `GuardRequest.Attributes`
- `GuardRequest.Context`
- `Subject.Attributes`
- `Resource.Attributes`

Trusted inputs are limited to:

- `Action`
- `Subject.Type`
- `Subject.Id`
- `Resource.Type`
- `Resource.Id`
- `TrustedSignals`

Why this matters:

- caller-controlled fields are easy to omit, falsify, or replay
- AI-generated tool arguments are untrusted by default
- safety decisions must depend on server-side evidence, not on self-reported request metadata

In the MVP, untrusted fields are still useful for audit snapshots and diagnostics, but they are not valid rule-match inputs.

## Action Contract

`Action` is not free text. It must be a normalized operation identifier selected from a finite registry, for example:

```text
photo.metadata.update
photo.visual.edit
content.publish
filesystem.delete
docker.inspect
```

This prevents the executor from interpreting vague or model-generated intent differently than the guardrail engine did. The executor must perform only the operation represented by the approved action.

## Audit and Replay Protection

The MVP treats trusted signals as time-bound evidence. A signal can be trustworthy in origin but still unsafe to use if it is stale.

As a result:

- trusted signal freshness is validated before final rule evaluation
- only decision-relevant trusted signals are freshness-checked
- audit generation is part of the MVP, not a future enhancement
- fail-closed audit behavior must not silently turn into executable success

See [Contracts](./contracts.md) for the exact rules and [CLI](./cli.md) for the machine-consumer contract.
