using A2G.AIGuardrails.Core;

namespace A2G.AIGuardrails.Tests;

public sealed class PolicyLoaderTests
{
    [Fact]
    public void LoadFromString_Rejects_Untrusted_Rule_Match_Path()
    {
        var yaml = """
            id: test-policy
            version: 1.0.0
            defaultDecision: deny
            trustedSignals:
              defaultMaxAgeSeconds: 300
            audit:
              enabled: true
            rules:
              - id: invalid-rule
                effect: deny
                match:
                  request.attributes.operation: delete
            """;

        var loader = new PolicyLoader();
        var result = loader.LoadFromString(yaml);

        Assert.False(result.Success);
        Assert.Contains(result.Errors, error => error.Contains("request.attributes.operation", StringComparison.Ordinal));
    }
}
