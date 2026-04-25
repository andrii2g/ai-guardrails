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

    [Theory]
    [InlineData("subject.attributes.role")]
    [InlineData("resource.attributes.owner")]
    [InlineData("context.environment")]
    public void LoadFromString_Rejects_All_Forbidden_Rule_Match_Paths(string forbiddenPath)
    {
        var yaml = $$"""
            id: test-policy
            version: 1.0.0
            defaultDecision: deny
            trustedSignals:
              defaultMaxAgeSeconds: 300
            audit:
              enabled: true
            rules:
              - id: invalid-rule
                effect: review
                match:
                  {{forbiddenPath}}: value
            """;

        var loader = new PolicyLoader();
        var result = loader.LoadFromString(yaml);

        Assert.False(result.Success);
        Assert.Contains(result.Errors, error => error.Contains(forbiddenPath, StringComparison.Ordinal));
    }

    [Fact]
    public void LoadFromString_Rejects_Dotted_Trusted_Signal_Key_Syntax()
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
                  trusted.content.category: extremist_symbol
            """;

        var loader = new PolicyLoader();
        var result = loader.LoadFromString(yaml);

        Assert.False(result.Success);
        Assert.Contains(result.Errors, error => error.Contains("trusted.content.category", StringComparison.Ordinal));
    }
}
