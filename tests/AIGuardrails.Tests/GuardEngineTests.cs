using A2G.AIGuardrails.Core;

namespace A2G.AIGuardrails.Tests;

public sealed class GuardEngineTests
{
    [Fact]
    public void Evaluate_Does_Not_Invalidate_Request_For_Stale_Unrelated_Trusted_Signal()
    {
        var policy = LoadPolicy("""
            id: test-policy
            version: 1.0.0
            defaultDecision: deny
            trustedSignals:
              defaultMaxAgeSeconds: 300
              maxAgeSecondsByKey:
                content_category: 120
            audit:
              enabled: false
            rules:
              - id: allow-metadata
                effect: allow
                match:
                  action: photo.metadata.update
                  resource.type: photo
              - id: deny-extremist
                effect: deny
                match:
                  action: photo.visual.edit
                  trusted.content_category: extremist_symbol
            """);

        var request = new GuardRequest
        {
            Subject = new Subject { Type = "service", Id = "photo-service" },
            Action = "photo.metadata.update",
            Resource = new Resource { Type = "photo", Id = "photo-1" },
            TrustedSignals = new Dictionary<string, TrustedSignal>
            {
                ["security_scan_result"] = new()
                {
                    Value = "clean",
                    Issuer = "scanner",
                    IssuedAtUtc = "2020-01-01T00:00:00Z"
                }
            }
        };

        var engine = new GuardEngine(policy, clock: new FakeClock("2026-04-25T12:00:00Z"));
        var result = engine.Evaluate(request);

        Assert.Equal(GuardEvaluationStatus.Evaluated, result.Status);
        Assert.Equal(DecisionType.Allow, result.Decision?.Decision);
    }

    [Fact]
    public void Evaluate_Returns_AuditWriteFailed_And_Retains_Decision_And_Audit_Event()
    {
        var policy = LoadPolicy("""
            id: test-policy
            version: 1.0.0
            defaultDecision: deny
            trustedSignals:
              defaultMaxAgeSeconds: 300
            audit:
              enabled: true
            rules:
              - id: allow-metadata
                effect: allow
                reason: Allowed.
                match:
                  action: photo.metadata.update
                  resource.type: photo
            """);

        var request = new GuardRequest
        {
            Subject = new Subject { Type = "service", Id = "photo-service" },
            Action = "photo.metadata.update",
            Resource = new Resource { Type = "photo", Id = "photo-1" }
        };

        var engine = new GuardEngine(
            policy,
            new ThrowingAuditSink(),
            AuditFailureMode.FailClosed,
            new FakeClock("2026-04-25T12:00:00Z"));

        var result = engine.Evaluate(request);

        Assert.Equal(GuardEvaluationStatus.AuditWriteFailed, result.Status);
        Assert.NotNull(result.Decision);
        Assert.NotNull(result.AuditEvent);
        Assert.False(result.ExecutionAllowed);
        Assert.Equal(DecisionType.Allow, result.Decision!.Decision);
    }

    [Fact]
    public void Evaluate_Captures_Exact_Trusted_Evidence_For_Winning_Rules()
    {
        var policy = LoadPolicy("""
            id: test-policy
            version: 1.0.0
            defaultDecision: deny
            trustedSignals:
              defaultMaxAgeSeconds: 300
            audit:
              enabled: true
            rules:
              - id: deny-extremist
                effect: deny
                risk: high
                reason: Extremist symbols are not allowed.
                match:
                  action: photo.visual.edit
                  trusted.content_category: extremist_symbol
                  trusted.content_category.issuer: server-side-image-moderation
            """);

        var request = new GuardRequest
        {
            Subject = new Subject { Type = "service", Id = "photo-service" },
            Action = "photo.visual.edit",
            Resource = new Resource { Type = "photo", Id = "photo-1" },
            TrustedSignals = new Dictionary<string, TrustedSignal>
            {
                ["content_category"] = new()
                {
                    Value = "extremist_symbol",
                    Issuer = "server-side-image-moderation",
                    Version = "2026-04-01",
                    IssuedAtUtc = "2026-04-25T11:59:00Z"
                }
            }
        };

        var engine = new GuardEngine(policy, clock: new FakeClock("2026-04-25T12:00:00Z"));
        var result = engine.Evaluate(request);

        Assert.Equal(GuardEvaluationStatus.Evaluated, result.Status);
        Assert.NotNull(result.AuditEvent);
        Assert.Collection(
            result.AuditEvent!.MatchedTrustedEvidence.OrderBy(item => item.Path, StringComparer.Ordinal),
            valueEvidence =>
            {
                Assert.Equal("trusted.content_category", valueEvidence.Path);
                Assert.Equal("value", valueEvidence.Field);
                Assert.Equal("extremist_symbol", valueEvidence.SignalValue);
                Assert.Equal("server-side-image-moderation", valueEvidence.SignalIssuer);
                Assert.Equal("2026-04-01", valueEvidence.SignalVersion);
            },
            issuerEvidence =>
            {
                Assert.Equal("trusted.content_category.issuer", issuerEvidence.Path);
                Assert.Equal("issuer", issuerEvidence.Field);
                Assert.Equal("server-side-image-moderation", issuerEvidence.Actual);
                Assert.Equal("2026-04-25T11:59:00Z", issuerEvidence.SignalIssuedAtUtc);
            });
    }

    private static GuardPolicy LoadPolicy(string yaml)
    {
        var loader = new PolicyLoader();
        var result = loader.LoadFromString(yaml);
        Assert.True(result.Success, string.Join(Environment.NewLine, result.Errors));
        return result.Policy!;
    }

    private sealed class ThrowingAuditSink : IAuditSink
    {
        public void Write(AuditEvent auditEvent) => throw new IOException("Audit sink failure.");
    }

    private sealed class FakeClock : IClock
    {
        private readonly DateTimeOffset _utcNow;

        public FakeClock(string utcNow)
        {
            _utcNow = DateTimeOffset.Parse(utcNow);
        }

        public DateTimeOffset UtcNow => _utcNow;
    }
}
