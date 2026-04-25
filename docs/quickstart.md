# AIGuardrails Quickstart

This document shows how to run the current CLI against the checked-in sample policy and request files.

Related documents:

- [Overview](./overview.md)
- [Contracts](./contracts.md)
- [CLI](./cli.md)

## Sample Assets

The repository includes runnable sample assets:

- [Default policy](/policies/default.policy.yaml)
- [Allow request](/examples/simple-cli/request-allow.json)
- [Deny request](/examples/simple-cli/request-deny.json)
- [Review request](/examples/simple-cli/request-review.json)

## Run the CLI

From the repository root:

```powershell
dotnet run --project .\src\AIGuardrails.Cli -- validate --policy .\policies\default.policy.yaml --request .\examples\simple-cli\request-allow.json --json
```

Write audit output to an NDJSON file:

```powershell
dotnet run --project .\src\AIGuardrails.Cli -- validate --policy .\policies\default.policy.yaml --request .\examples\simple-cli\request-review.json --audit .\audit.ndjson --json
```

## Example Scenarios

Allow:

```powershell
dotnet run --project .\src\AIGuardrails.Cli -- validate --policy .\policies\default.policy.yaml --request .\examples\simple-cli\request-allow.json --json
```

Deny:

```powershell
dotnet run --project .\src\AIGuardrails.Cli -- validate --policy .\policies\default.policy.yaml --request .\examples\simple-cli\request-deny.json --json
```

Require approval:

```powershell
dotnet run --project .\src\AIGuardrails.Cli -- validate --policy .\policies\default.policy.yaml --request .\examples\simple-cli\request-review.json --json
```

## Exit Codes

```text
0 -> Allow
1 -> RequireApproval
2 -> Deny
3 -> InvalidRequest
4 -> InvalidPolicy
5 -> RuntimeError
6 -> AuditWriteFailed
```

Safe automation gating rule:

```text
exit code == 0
```

or, if consuming JSON:

```text
status == "Evaluated" && executionAllowed == true
```

Do not gate on `decision.decision == "Allow"` alone.

## Notes

The checked-in sample policy uses long trusted-signal freshness windows so the example request files remain runnable over time. Tight freshness policies should be enforced in real deployments.
