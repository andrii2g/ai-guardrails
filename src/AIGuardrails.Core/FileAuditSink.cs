using System.Text.Json;
using System.Text.Json.Serialization;

namespace A2G.AIGuardrails.Core;

public sealed class FileAuditSink : IAuditSink
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _path;

    public FileAuditSink(string path)
    {
        _path = string.IsNullOrWhiteSpace(path)
            ? throw new ArgumentException("Audit path is required.", nameof(path))
            : path;
    }

    public void Write(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var payload = JsonSerializer.Serialize(auditEvent, SerializerOptions);
        File.AppendAllText(_path, payload + Environment.NewLine);
    }
}
