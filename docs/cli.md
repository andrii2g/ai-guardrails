# AIGuardrails CLI

This document describes the CLI contract for AIGuardrails, including process exit codes and the mandatory JSON output envelope.

Related documents:

- [Overview](./overview.md)
- [Contracts](./contracts.md)
- [Detailed design in PLAN.md](../PLAN.md)

## Purpose

The CLI evaluates a request against a policy file and exposes a machine-safe contract for local testing, CI, and service integration.

Primary command:

```bash
aiguardrails validate --policy policies/default.policy.yaml --request request.json
```

Optional audit output file:

```bash
aiguardrails validate --policy policies/default.policy.yaml --request request.json --audit audit.ndjson
```

Optional JSON output:

```bash
aiguardrails validate --policy policies/default.policy.yaml --request request.json --json
```

## Exit Codes

The CLI exit code contract is:

```text
0 -> Allow
1 -> RequireApproval
2 -> Deny
3 -> Invalid request
4 -> Invalid policy
5 -> Runtime error
6 -> Audit write failure
```

Consumers may safely gate execution on process exit code `0`.

## JSON Envelope

When `--json` is used, the CLI must always emit one top-level JSON envelope for both success and failure cases.

Required top-level fields:

```text
schemaVersion
status
success
exitCode
executionAllowed
decision
auditEvent
errors
```

Allowed `status` values:

```text
Evaluated
InvalidRequest
InvalidPolicy
RuntimeError
AuditWriteFailed
```

Rules:

- `success` is true only when `status == Evaluated`
- `executionAllowed` is true only when `status == Evaluated` and `decision.decision == Allow`
- `decision` may be present for `Evaluated` and `AuditWriteFailed`
- `auditEvent` may be present when generated, including `AuditWriteFailed`
- machine consumers must not gate on `decision.decision == "Allow"` alone

Safe machine-consumer gating rules:

```text
process exit code == 0
```

or:

```text
status == "Evaluated" && executionAllowed == true
```

## Success Example

```json
{
  "schemaVersion": "1.0",
  "status": "Evaluated",
  "success": true,
  "exitCode": 0,
  "executionAllowed": true,
  "decision": {
    "decision": "Allow",
    "risk": "Low",
    "reason": "Photo metadata updates are allowed.",
    "matchedRules": [
      "allow-photo-metadata-update"
    ],
    "matchedRuleReasons": [],
    "diagnostics": []
  },
  "auditEvent": null,
  "errors": []
}
```

## Review or Deny

The CLI must distinguish policy outcomes from failures:

- `RequireApproval` returns exit code `1`
- `Deny` returns exit code `2`
- both still use `status = "Evaluated"` because evaluation succeeded

## Invalid Request

Invalid requests are input failures, not denials.

Expected behavior:

- `status = "InvalidRequest"`
- `exitCode = 3`
- `executionAllowed = false`
- `decision = null`

Example:

```json
{
  "schemaVersion": "1.0",
  "status": "InvalidRequest",
  "success": false,
  "exitCode": 3,
  "executionAllowed": false,
  "decision": null,
  "auditEvent": null,
  "errors": [
    "Action is required."
  ]
}
```

## Invalid Policy

Invalid policies must fail during policy loading, not during evaluation.

Expected behavior:

- `status = "InvalidPolicy"`
- `exitCode = 4`
- `executionAllowed = false`
- `decision = null`

## Runtime Error

Unexpected operational failures during evaluation must return:

- `status = "RuntimeError"`
- `exitCode = 5`
- `executionAllowed = false`
- `decision = null`

The outer CLI command boundary must also map unhandled exceptions to exit code `5`.

## Audit Write Failure

Fail-closed audit failures are not executable, even if the decision was already computed as `Allow`.

Expected behavior:

- `status = "AuditWriteFailed"`
- `success = false`
- `exitCode = 6`
- `executionAllowed = false`
- computed `decision` may still be present
- generated `auditEvent` may still be present

Example:

```json
{
  "schemaVersion": "1.0",
  "status": "AuditWriteFailed",
  "success": false,
  "exitCode": 6,
  "executionAllowed": false,
  "decision": {
    "decision": "Allow",
    "risk": "Low",
    "reason": "Photo metadata updates are allowed.",
    "matchedRules": [
      "allow-photo-metadata-update"
    ],
    "matchedRuleReasons": [],
    "diagnostics": []
  },
  "auditEvent": {
    "eventId": "evt-123",
    "policyId": "default-ai-guardrails",
    "policyVersion": "1.0.0",
    "decision": "Allow",
    "risk": "Low",
    "reason": "Photo metadata updates are allowed.",
    "matchedRules": [
      "allow-photo-metadata-update"
    ],
    "matchedTrustedEvidence": [],
    "requestSnapshot": {}
  },
  "errors": [
    "Failed to write audit event to audit.ndjson."
  ]
}
```

Even in this case, execution is forbidden because:

```text
status != Evaluated
executionAllowed == false
exitCode == 6
```
