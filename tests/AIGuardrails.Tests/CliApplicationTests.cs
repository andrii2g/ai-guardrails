using System.Text.Json;
using A2G.AIGuardrails.Cli;

namespace A2G.AIGuardrails.Tests;

public sealed class CliApplicationTests
{
    [Fact]
    public void Run_Produces_Status_First_Json_Envelope_For_Audit_Write_Failure()
    {
        var root = Directory.CreateTempSubdirectory();
        try
        {
            var policyPath = Path.Combine(root.FullName, "policy.yaml");
            var requestPath = Path.Combine(root.FullName, "request.json");

            File.WriteAllText(policyPath, """
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

            File.WriteAllText(requestPath, """
                {
                  "subject": {
                    "type": "service",
                    "id": "photo-service"
                  },
                  "action": "photo.metadata.update",
                  "resource": {
                    "type": "photo",
                    "id": "photo-1"
                  }
                }
                """);

            using var stdout = new StringWriter();
            using var stderr = new StringWriter();

            var app = new CliApplication();
            var exitCode = app.Run(
                ["validate", "--policy", policyPath, "--request", requestPath, "--audit", root.FullName, "--json"],
                stdout,
                stderr);

            using var document = JsonDocument.Parse(stdout.ToString());
            var rootElement = document.RootElement;

            Assert.Equal(6, exitCode);
            Assert.Equal("AuditWriteFailed", rootElement.GetProperty("status").GetString());
            Assert.False(rootElement.GetProperty("success").GetBoolean());
            Assert.False(rootElement.GetProperty("executionAllowed").GetBoolean());
            Assert.Equal("Allow", rootElement.GetProperty("decision").GetProperty("decision").GetString());
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public void Run_Produces_InvalidPolicy_Envelope_For_Invalid_Policy()
    {
        var root = Directory.CreateTempSubdirectory();
        try
        {
            var policyPath = Path.Combine(root.FullName, "policy.yaml");
            var requestPath = Path.Combine(root.FullName, "request.json");

            File.WriteAllText(policyPath, """
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
                """);

            File.WriteAllText(requestPath, """
                {
                  "subject": {
                    "type": "service",
                    "id": "photo-service"
                  },
                  "action": "photo.metadata.update",
                  "resource": {
                    "type": "photo",
                    "id": "photo-1"
                  }
                }
                """);

            using var stdout = new StringWriter();
            using var stderr = new StringWriter();

            var app = new CliApplication();
            var exitCode = app.Run(
                ["validate", "--policy", policyPath, "--request", requestPath, "--json"],
                stdout,
                stderr);

            using var document = JsonDocument.Parse(stdout.ToString());
            var rootElement = document.RootElement;

            Assert.Equal(4, exitCode);
            Assert.Equal("InvalidPolicy", rootElement.GetProperty("status").GetString());
            Assert.False(rootElement.GetProperty("executionAllowed").GetBoolean());
            Assert.Equal(JsonValueKind.Null, rootElement.GetProperty("decision").ValueKind);
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Theory]
    [InlineData("""
        id: test-policy
        version: 1.0.0
        defaultDecision: deny
        trustedSignals:
          defaultMaxAgeSeconds: 300
        audit:
          enabled: false
        rules:
          - id: review-prod
            effect: review
            reason: Review required.
            match:
              action: content.publish
              trusted.deployment_environment: production
        """, """
        {
          "subject": {
            "type": "service",
            "id": "publisher"
          },
          "action": "content.publish",
          "resource": {
            "type": "article",
            "id": "article-1"
          },
          "trustedSignals": {
            "deployment_environment": {
              "value": "production",
              "issuer": "runtime-environment-provider",
              "issuedAtUtc": "2026-04-25T12:00:00Z"
            }
          }
        }
        """, 1, "RequireApproval")]
    [InlineData("""
        id: test-policy
        version: 1.0.0
        defaultDecision: allow
        trustedSignals:
          defaultMaxAgeSeconds: 300
        audit:
          enabled: false
        rules:
          - id: deny-delete
            effect: deny
            reason: Delete denied.
            match:
              action: filesystem.delete
              resource.type: filesystem
        """, """
        {
          "subject": {
            "type": "service",
            "id": "executor"
          },
          "action": "filesystem.delete",
          "resource": {
            "type": "filesystem",
            "id": "/tmp"
          }
        }
        """, 2, "Deny")]
    public void Run_Produces_Evaluated_Envelope_For_Review_And_Deny(string policyYaml, string requestJson, int expectedExitCode, string expectedDecision)
    {
        var root = Directory.CreateTempSubdirectory();
        try
        {
            var policyPath = Path.Combine(root.FullName, "policy.yaml");
            var requestPath = Path.Combine(root.FullName, "request.json");

            File.WriteAllText(policyPath, policyYaml);
            File.WriteAllText(requestPath, requestJson);

            using var stdout = new StringWriter();
            using var stderr = new StringWriter();

            var app = new CliApplication();
            var exitCode = app.Run(
                ["validate", "--policy", policyPath, "--request", requestPath, "--json"],
                stdout,
                stderr);

            using var document = JsonDocument.Parse(stdout.ToString());
            var rootElement = document.RootElement;

            Assert.Equal(expectedExitCode, exitCode);
            Assert.Equal("Evaluated", rootElement.GetProperty("status").GetString());
            Assert.False(rootElement.GetProperty("executionAllowed").GetBoolean());
            Assert.Equal(expectedDecision, rootElement.GetProperty("decision").GetProperty("decision").GetString());
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
}
