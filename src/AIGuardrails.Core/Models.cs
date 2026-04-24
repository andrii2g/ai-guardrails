namespace A2G.AIGuardrails.Core;

public sealed class GuardRequest
{
    public required Subject Subject { get; init; }
    public required string Action { get; init; }
    public required Resource Resource { get; init; }
    public Dictionary<string, string> Attributes { get; init; } = new();
    public Dictionary<string, TrustedSignal> TrustedSignals { get; init; } = new();
    public Dictionary<string, string> Context { get; init; } = new();
    public string? CorrelationId { get; init; }
}

public sealed class Subject
{
    public required string Type { get; init; }
    public required string Id { get; init; }
    public Dictionary<string, string> Attributes { get; init; } = new();
}

public sealed class Resource
{
    public required string Type { get; init; }
    public required string Id { get; init; }
    public Dictionary<string, string> Attributes { get; init; } = new();
}

public sealed class TrustedSignal
{
    public required string Value { get; init; }
    public required string Issuer { get; init; }
    public string? Version { get; init; }
    public required string IssuedAtUtc { get; init; }
}

public sealed class GuardPolicy
{
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required string DefaultDecision { get; init; }
    public AuditPolicy Audit { get; init; } = new();
    public TrustedSignalFreshnessPolicy TrustedSignals { get; init; } = new();
    public List<PolicyRule> Rules { get; init; } = new();
}

public sealed class PolicyRule
{
    public required string Id { get; init; }
    public required string Effect { get; init; }
    public Dictionary<string, string> Match { get; init; } = new();
    public string Risk { get; init; } = "low";
    public string? Reason { get; init; }
}

public sealed class AuditPolicy
{
    public bool Enabled { get; init; } = true;
    public List<string> IncludeFields { get; init; } = new();
    public List<string> RedactFields { get; init; } = new();
}

public sealed class TrustedSignalFreshnessPolicy
{
    public int DefaultMaxAgeSeconds { get; init; } = 300;
    public Dictionary<string, int> MaxAgeSecondsByKey { get; init; } = new();
}

public sealed class PolicyLoadResult
{
    public bool Success { get; init; }
    public GuardPolicy? Policy { get; init; }
    public List<string> Errors { get; init; } = new();

    public static PolicyLoadResult Valid(GuardPolicy policy) => new()
    {
        Success = true,
        Policy = policy
    };

    public static PolicyLoadResult Invalid(IEnumerable<string> errors) => new()
    {
        Success = false,
        Policy = null,
        Errors = errors.ToList()
    };
}

public sealed class GuardDecision
{
    public required DecisionType Decision { get; init; }
    public required RiskLevel Risk { get; init; }
    public required string Reason { get; init; }
    public List<string> MatchedRules { get; init; } = new();
    public List<MatchedRuleReason> MatchedRuleReasons { get; init; } = new();
    public List<string> Diagnostics { get; init; } = new();
}

public sealed class MatchedRuleReason
{
    public required string RuleId { get; init; }
    public required string Effect { get; init; }
    public required RiskLevel Risk { get; init; }
    public required string Reason { get; init; }
}

public sealed class AuditEvent
{
    public required string EventId { get; init; }
    public required string EvaluatedAtUtc { get; init; }
    public string? CorrelationId { get; init; }
    public required string PolicyId { get; init; }
    public required string PolicyVersion { get; init; }
    public required string SubjectType { get; init; }
    public required string SubjectId { get; init; }
    public required string Action { get; init; }
    public required string ResourceType { get; init; }
    public required string ResourceId { get; init; }
    public required DecisionType Decision { get; init; }
    public required RiskLevel Risk { get; init; }
    public required string Reason { get; init; }
    public List<string> MatchedRules { get; init; } = new();
    public List<MatchedTrustedEvidence> MatchedTrustedEvidence { get; init; } = new();
    public Dictionary<string, string> RequestSnapshot { get; init; } = new();
}

public sealed class MatchedTrustedEvidence
{
    public required string RuleId { get; init; }
    public required string Path { get; init; }
    public required string SignalKey { get; init; }
    public required string Field { get; init; }
    public required string Expected { get; init; }
    public required string Actual { get; init; }
    public required string SignalValue { get; init; }
    public required string SignalIssuer { get; init; }
    public string? SignalVersion { get; init; }
    public required string SignalIssuedAtUtc { get; init; }
}

public sealed class GuardEvaluationResult
{
    public required GuardEvaluationStatus Status { get; init; }
    public bool Success => Status == GuardEvaluationStatus.Evaluated;
    public bool ExecutionAllowed => Status == GuardEvaluationStatus.Evaluated && Decision?.Decision == DecisionType.Allow;
    public GuardDecision? Decision { get; init; }
    public AuditEvent? AuditEvent { get; init; }
    public List<string> Errors { get; init; } = new();

    public static GuardEvaluationResult Evaluated(GuardDecision decision, AuditEvent? auditEvent) => new()
    {
        Status = GuardEvaluationStatus.Evaluated,
        Decision = decision,
        AuditEvent = auditEvent
    };

    public static GuardEvaluationResult InvalidRequest(IEnumerable<string> errors) => new()
    {
        Status = GuardEvaluationStatus.InvalidRequest,
        Errors = errors.ToList()
    };

    public static GuardEvaluationResult AuditWriteFailed(GuardDecision decision, AuditEvent auditEvent, IEnumerable<string> errors) => new()
    {
        Status = GuardEvaluationStatus.AuditWriteFailed,
        Decision = decision,
        AuditEvent = auditEvent,
        Errors = errors.ToList()
    };

    public static GuardEvaluationResult RuntimeError(IEnumerable<string> errors) => new()
    {
        Status = GuardEvaluationStatus.RuntimeError,
        Errors = errors.ToList()
    };
}
