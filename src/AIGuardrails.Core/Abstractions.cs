using System.Text.Json.Serialization;

namespace A2G.AIGuardrails.Core;

public interface IPolicyLoader
{
    PolicyLoadResult LoadFromFile(string path);
    PolicyLoadResult LoadFromString(string yaml);
}

public interface IGuardEngine
{
    GuardEvaluationResult Evaluate(GuardRequest request);
}

public interface IAuditSink
{
    void Write(AuditEvent auditEvent);
}

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DecisionType
{
    Allow,
    Deny,
    RequireApproval
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RiskLevel
{
    Low,
    Medium,
    High
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum GuardEvaluationStatus
{
    Evaluated,
    InvalidRequest,
    AuditWriteFailed,
    RuntimeError
}

public enum AuditFailureMode
{
    FailClosed,
    BestEffort
}
