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
}
