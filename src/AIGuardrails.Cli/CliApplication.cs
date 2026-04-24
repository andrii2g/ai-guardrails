using System.Text.Json;
using System.Text.Json.Serialization;
using AIGuardrails.Core;

namespace AIGuardrails.Cli;

public sealed class CliApplication
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IPolicyLoader _policyLoader;

    public CliApplication(IPolicyLoader? policyLoader = null)
    {
        _policyLoader = policyLoader ?? new PolicyLoader();
    }

    public int Run(string[] args, TextWriter stdout, TextWriter stderr)
    {
        CliOptions? options;
        try
        {
            options = CliOptions.Parse(args);
        }
        catch (Exception ex)
        {
            return WriteFailure(
                new CliEnvelope
                {
                    SchemaVersion = "1.0",
                    Status = "RuntimeError",
                    Success = false,
                    ExitCode = 5,
                    ExecutionAllowed = false,
                    Errors = new List<string> { ex.Message }
                },
                false,
                stdout,
                stderr);
        }

        var loadResult = _policyLoader.LoadFromFile(options.PolicyPath);
        if (!loadResult.Success || loadResult.Policy is null)
        {
            return WriteFailure(
                new CliEnvelope
                {
                    SchemaVersion = "1.0",
                    Status = "InvalidPolicy",
                    Success = false,
                    ExitCode = 4,
                    ExecutionAllowed = false,
                    Errors = loadResult.Errors
                },
                options.Json,
                stdout,
                stderr);
        }

        GuardRequest? request;
        try
        {
            var requestJson = File.ReadAllText(options.RequestPath);
            request = JsonSerializer.Deserialize<GuardRequest>(requestJson, SerializerOptions);
        }
        catch (Exception ex)
        {
            return WriteFailure(
                new CliEnvelope
                {
                    SchemaVersion = "1.0",
                    Status = "InvalidRequest",
                    Success = false,
                    ExitCode = 3,
                    ExecutionAllowed = false,
                    Errors = new List<string> { ex.Message }
                },
                options.Json,
                stdout,
                stderr);
        }

        var auditSink = options.AuditPath is null ? null : new FileAuditSink(options.AuditPath);
        var engine = new GuardEngine(loadResult.Policy, auditSink);
        var result = engine.Evaluate(request!);

        var envelope = CreateEnvelope(result);
        return WriteResult(envelope, options.Json, stdout, stderr);
    }

    public static CliEnvelope CreateEnvelope(GuardEvaluationResult result)
    {
        var exitCode = result.Status switch
        {
            GuardEvaluationStatus.InvalidRequest => 3,
            GuardEvaluationStatus.RuntimeError => 5,
            GuardEvaluationStatus.AuditWriteFailed => 6,
            GuardEvaluationStatus.Evaluated when result.Decision?.Decision == DecisionType.Allow => 0,
            GuardEvaluationStatus.Evaluated when result.Decision?.Decision == DecisionType.RequireApproval => 1,
            GuardEvaluationStatus.Evaluated => 2,
            _ => 5
        };

        return new CliEnvelope
        {
            SchemaVersion = "1.0",
            Status = result.Status.ToString(),
            Success = result.Status == GuardEvaluationStatus.Evaluated,
            ExitCode = exitCode,
            ExecutionAllowed = result.ExecutionAllowed,
            Decision = result.Decision,
            AuditEvent = result.AuditEvent,
            Errors = result.Errors
        };
    }

    private static int WriteResult(CliEnvelope envelope, bool json, TextWriter stdout, TextWriter stderr)
    {
        if (json)
        {
            stdout.WriteLine(JsonSerializer.Serialize(envelope, SerializerOptions));
            return envelope.ExitCode;
        }

        if (envelope.Status == "Evaluated" && envelope.Decision is not null)
        {
            stdout.WriteLine($"{envelope.Decision.Decision} ({envelope.Decision.Risk}): {envelope.Decision.Reason}");
            if (envelope.Decision.MatchedRules.Count > 0)
            {
                stdout.WriteLine($"Matched rules: {string.Join(", ", envelope.Decision.MatchedRules)}");
            }
        }
        else
        {
            stderr.WriteLine($"{envelope.Status} ({envelope.ExitCode})");
            foreach (var error in envelope.Errors)
            {
                stderr.WriteLine(error);
            }
        }

        return envelope.ExitCode;
    }

    private static int WriteFailure(CliEnvelope envelope, bool json, TextWriter stdout, TextWriter stderr)
        => WriteResult(envelope, json, stdout, stderr);
}

public sealed class CliEnvelope
{
    public required string SchemaVersion { get; init; }
    public required string Status { get; init; }
    public required bool Success { get; init; }
    public required int ExitCode { get; init; }
    public required bool ExecutionAllowed { get; init; }
    public GuardDecision? Decision { get; init; }
    public AuditEvent? AuditEvent { get; init; }
    public List<string> Errors { get; init; } = new();
}

internal sealed class CliOptions
{
    public required string PolicyPath { get; init; }
    public required string RequestPath { get; init; }
    public string? AuditPath { get; init; }
    public bool Json { get; init; }

    public static CliOptions Parse(string[] args)
    {
        if (args.Length == 0 || !string.Equals(args[0], "validate", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Usage: aiguardrails validate --policy <path> --request <path> [--audit <path>] [--json]");
        }

        string? policyPath = null;
        string? requestPath = null;
        string? auditPath = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--policy":
                    policyPath = ReadValue(args, ref i, "--policy");
                    break;
                case "--request":
                    requestPath = ReadValue(args, ref i, "--request");
                    break;
                case "--audit":
                    auditPath = ReadValue(args, ref i, "--audit");
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new InvalidOperationException($"Unknown argument '{args[i]}'.");
            }
        }

        if (string.IsNullOrWhiteSpace(policyPath))
        {
            throw new InvalidOperationException("--policy is required.");
        }

        if (string.IsNullOrWhiteSpace(requestPath))
        {
            throw new InvalidOperationException("--request is required.");
        }

        return new CliOptions
        {
            PolicyPath = policyPath,
            RequestPath = requestPath,
            AuditPath = auditPath,
            Json = json
        };
    }

    private static string ReadValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new InvalidOperationException($"{option} requires a value.");
        }

        index++;
        return args[index];
    }
}
