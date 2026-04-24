using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;

namespace AIGuardrails.Core;

public sealed class PolicyLoader : IPolicyLoader
{
    private static readonly HashSet<string> TopLevelKeys = new(StringComparer.Ordinal)
    {
        "id",
        "version",
        "defaultDecision",
        "audit",
        "trustedSignals",
        "rules"
    };

    private static readonly HashSet<string> RuleKeys = new(StringComparer.Ordinal)
    {
        "id",
        "effect",
        "match",
        "risk",
        "reason"
    };

    private static readonly HashSet<string> AuditKeys = new(StringComparer.Ordinal)
    {
        "enabled",
        "includeFields",
        "redactFields"
    };

    private static readonly HashSet<string> TrustedSignalKeys = new(StringComparer.Ordinal)
    {
        "defaultMaxAgeSeconds",
        "maxAgeSecondsByKey"
    };

    private static readonly HashSet<string> AllowedDecisions = new(StringComparer.Ordinal)
    {
        "allow",
        "deny",
        "review"
    };

    private static readonly HashSet<string> AllowedRiskValues = new(StringComparer.Ordinal)
    {
        "low",
        "medium",
        "high"
    };

    public PolicyLoadResult LoadFromFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return PolicyLoadResult.Invalid(new[] { "Policy path is required." });
        }

        try
        {
            return LoadFromString(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            return PolicyLoadResult.Invalid(new[] { $"Failed to read policy file '{path}': {ex.Message}" });
        }
    }

    public PolicyLoadResult LoadFromString(string yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml))
        {
            return PolicyLoadResult.Invalid(new[] { "Policy YAML is required." });
        }

        try
        {
            using var reader = new StringReader(yaml);
            var stream = new YamlStream();
            stream.Load(reader);

            if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode root)
            {
                return PolicyLoadResult.Invalid(new[] { "Policy root must be a single YAML mapping." });
            }

            var errors = new List<string>();
            ValidateAllowedKeys(root, TopLevelKeys, "policy", errors);

            var id = GetRequiredString(root, "id", errors);
            var version = GetRequiredString(root, "version", errors);
            var defaultDecision = GetRequiredString(root, "defaultDecision", errors)?.ToLowerInvariant();

            if (defaultDecision is not null && !AllowedDecisions.Contains(defaultDecision))
            {
                errors.Add($"Unsupported defaultDecision '{defaultDecision}'.");
            }

            var auditNode = GetRequiredMapping(root, "audit", errors);
            var trustedSignalsNode = GetRequiredMapping(root, "trustedSignals", errors);
            var rulesNode = GetRequiredSequence(root, "rules", errors);

            var auditPolicy = ParseAuditPolicy(auditNode, errors);
            var freshnessPolicy = ParseFreshnessPolicy(trustedSignalsNode, errors);
            var rules = ParseRules(rulesNode, errors);

            if (errors.Count > 0 || id is null || version is null || defaultDecision is null)
            {
                return PolicyLoadResult.Invalid(errors);
            }

            var policy = new GuardPolicy
            {
                Id = id,
                Version = version,
                DefaultDecision = defaultDecision,
                Audit = auditPolicy,
                TrustedSignals = freshnessPolicy,
                Rules = rules
            };

            return PolicyLoadResult.Valid(policy);
        }
        catch (Exception ex)
        {
            return PolicyLoadResult.Invalid(new[] { $"Malformed YAML: {ex.Message}" });
        }
    }

    private static AuditPolicy ParseAuditPolicy(YamlMappingNode? node, List<string> errors)
    {
        if (node is null)
        {
            return new AuditPolicy();
        }

        ValidateAllowedKeys(node, AuditKeys, "audit", errors);

        var enabled = GetOptionalBool(node, "enabled", errors) ?? true;
        var includeFields = GetOptionalStringList(node, "includeFields", errors);
        var redactFields = GetOptionalStringList(node, "redactFields", errors);

        foreach (var includeField in includeFields)
        {
            var error = PathGrammar.ValidateAuditPath(includeField);
            if (error is not null)
            {
                errors.Add($"Invalid audit include field path '{includeField}': {error}");
            }
        }

        foreach (var redactField in redactFields)
        {
            var error = PathGrammar.ValidateAuditPath(redactField);
            if (error is not null)
            {
                errors.Add($"Invalid audit redact field path '{redactField}': {error}");
            }
        }

        return new AuditPolicy
        {
            Enabled = enabled,
            IncludeFields = includeFields,
            RedactFields = redactFields
        };
    }

    private static TrustedSignalFreshnessPolicy ParseFreshnessPolicy(YamlMappingNode? node, List<string> errors)
    {
        if (node is null)
        {
            return new TrustedSignalFreshnessPolicy();
        }

        ValidateAllowedKeys(node, TrustedSignalKeys, "trustedSignals", errors);

        var defaultMaxAgeSeconds = GetRequiredInt(node, "defaultMaxAgeSeconds", errors);
        var perKey = new Dictionary<string, int>(StringComparer.Ordinal);

        var mapping = GetOptionalMapping(node, "maxAgeSecondsByKey");
        if (mapping is not null)
        {
            foreach (var entry in mapping.Children)
            {
                var key = (entry.Key as YamlScalarNode)?.Value ?? string.Empty;
                if (!PathGrammar.IsTrustedSignalKey(key))
                {
                    errors.Add($"Invalid trusted signal key in trustedSignals.maxAgeSecondsByKey: '{key}'.");
                    continue;
                }

                if (!TryGetInt(entry.Value, out var maxAge))
                {
                    errors.Add($"Invalid per-key trusted signal max age for '{key}'.");
                    continue;
                }

                if (maxAge <= 0)
                {
                    errors.Add($"Invalid per-key trusted signal max age for '{key}'.");
                    continue;
                }

                perKey[key] = maxAge;
            }
        }

        if (defaultMaxAgeSeconds <= 0)
        {
            errors.Add("Invalid trustedSignals.defaultMaxAgeSeconds.");
        }

        return new TrustedSignalFreshnessPolicy
        {
            DefaultMaxAgeSeconds = defaultMaxAgeSeconds,
            MaxAgeSecondsByKey = perKey
        };
    }

    private static List<PolicyRule> ParseRules(YamlSequenceNode? node, List<string> errors)
    {
        var rules = new List<PolicyRule>();
        if (node is null)
        {
            return rules;
        }

        var seenIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (var child in node.Children)
        {
            if (child is not YamlMappingNode ruleNode)
            {
                errors.Add("Each rule must be a YAML mapping.");
                continue;
            }

            ValidateAllowedKeys(ruleNode, RuleKeys, "rule", errors);

            var id = GetRequiredString(ruleNode, "id", errors);
            var effect = GetRequiredString(ruleNode, "effect", errors)?.ToLowerInvariant();
            var risk = GetOptionalString(ruleNode, "risk")?.ToLowerInvariant() ?? "low";
            var reason = GetOptionalString(ruleNode, "reason");
            var matchNode = GetOptionalMapping(ruleNode, "match");
            var match = new Dictionary<string, string>(StringComparer.Ordinal);

            if (effect is not null && !AllowedDecisions.Contains(effect))
            {
                errors.Add($"Unsupported effect '{effect}'.");
            }

            if (!AllowedRiskValues.Contains(risk))
            {
                errors.Add($"Invalid risk value '{risk}'.");
            }

            if (id is not null && !seenIds.Add(id))
            {
                errors.Add($"Duplicate rule ID '{id}'.");
            }

            if (matchNode is not null)
            {
                foreach (var entry in matchNode.Children)
                {
                    var path = (entry.Key as YamlScalarNode)?.Value ?? string.Empty;
                    var value = (entry.Value as YamlScalarNode)?.Value ?? string.Empty;

                    var pathError = PathGrammar.ValidateRuleMatchPath(path);
                    if (pathError is not null)
                    {
                        errors.Add($"Invalid rule match path '{path}': {pathError}");
                        continue;
                    }

                    var wildcardError = WildcardMatcher.ValidatePattern(value);
                    if (wildcardError is not null)
                    {
                        errors.Add($"Invalid wildcard expression '{value}' for path '{path}': {wildcardError}");
                        continue;
                    }

                    match[path] = value;
                }
            }

            if (id is null || effect is null)
            {
                continue;
            }

            rules.Add(new PolicyRule
            {
                Id = id,
                Effect = effect,
                Match = match,
                Risk = risk,
                Reason = reason
            });
        }

        return rules;
    }

    private static void ValidateAllowedKeys(YamlMappingNode node, HashSet<string> allowedKeys, string scope, List<string> errors)
    {
        foreach (var key in node.Children.Keys.OfType<YamlScalarNode>().Select(k => k.Value ?? string.Empty))
        {
            if (!allowedKeys.Contains(key))
            {
                errors.Add($"Unknown {scope} field '{key}'.");
            }
        }
    }

    private static string? GetRequiredString(YamlMappingNode node, string key, List<string> errors)
    {
        var value = GetOptionalString(node, key);
        if (value is null)
        {
            errors.Add($"Missing `{key}`.");
        }

        return value;
    }

    private static int GetRequiredInt(YamlMappingNode node, string key, List<string> errors)
    {
        if (!TryGetScalar(node, key, out var scalar) || !int.TryParse(scalar, out var value))
        {
            errors.Add($"Missing or invalid `{key}`.");
            return 0;
        }

        return value;
    }

    private static bool? GetOptionalBool(YamlMappingNode node, string key, List<string> errors)
    {
        if (!TryGetScalar(node, key, out var scalar))
        {
            return null;
        }

        if (bool.TryParse(scalar, out var value))
        {
            return value;
        }

        errors.Add($"Invalid boolean value for `{key}`.");
        return null;
    }

    private static string? GetOptionalString(YamlMappingNode node, string key)
        => TryGetScalar(node, key, out var scalar) ? scalar : null;

    private static List<string> GetOptionalStringList(YamlMappingNode node, string key, List<string> errors)
    {
        var values = new List<string>();
        if (!node.Children.TryGetValue(new YamlScalarNode(key), out var child))
        {
            return values;
        }

        if (child is not YamlSequenceNode sequence)
        {
            errors.Add($"`{key}` must be a YAML sequence.");
            return values;
        }

        foreach (var item in sequence.Children)
        {
            if (item is not YamlScalarNode scalar)
            {
                errors.Add($"`{key}` entries must be scalar values.");
                continue;
            }

            values.Add(scalar.Value ?? string.Empty);
        }

        return values;
    }

    private static YamlMappingNode? GetRequiredMapping(YamlMappingNode node, string key, List<string> errors)
    {
        var mapping = GetOptionalMapping(node, key);
        if (mapping is null)
        {
            errors.Add($"Missing `{key}`.");
        }

        return mapping;
    }

    private static YamlSequenceNode? GetRequiredSequence(YamlMappingNode node, string key, List<string> errors)
    {
        if (!node.Children.TryGetValue(new YamlScalarNode(key), out var child) || child is not YamlSequenceNode sequence)
        {
            errors.Add($"Missing `{key}`.");
            return null;
        }

        return sequence;
    }

    private static YamlMappingNode? GetOptionalMapping(YamlMappingNode node, string key)
        => node.Children.TryGetValue(new YamlScalarNode(key), out var child) && child is YamlMappingNode mapping
            ? mapping
            : null;

    private static bool TryGetScalar(YamlMappingNode node, string key, out string value)
    {
        if (node.Children.TryGetValue(new YamlScalarNode(key), out var child) && child is YamlScalarNode scalar)
        {
            value = scalar.Value ?? string.Empty;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetInt(YamlNode node, out int value)
    {
        value = 0;
        return node is YamlScalarNode scalar && int.TryParse(scalar.Value, out value);
    }
}

internal static class PathGrammar
{
    private static readonly Regex TrustedSignalKeyPattern = new("^[A-Za-z][A-Za-z0-9_-]{0,63}$", RegexOptions.Compiled);
    private static readonly HashSet<string> ExactRulePaths = new(StringComparer.Ordinal)
    {
        "action",
        "subject.type",
        "subject.id",
        "resource.type",
        "resource.id"
    };

    public static bool IsTrustedSignalKey(string value) => !string.IsNullOrWhiteSpace(value) && TrustedSignalKeyPattern.IsMatch(value);

    public static string? ValidateRuleMatchPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "Path is required.";
        }

        if (ExactRulePaths.Contains(path))
        {
            return null;
        }

        if (path.StartsWith("trusted.", StringComparison.Ordinal))
        {
            return TryParseTrustedPath(path, out _) ? null : "Trusted path is invalid.";
        }

        if (path.StartsWith("request.attributes.", StringComparison.Ordinal) ||
            path.StartsWith("subject.attributes.", StringComparison.Ordinal) ||
            path.StartsWith("resource.attributes.", StringComparison.Ordinal) ||
            path.StartsWith("context.", StringComparison.Ordinal) ||
            path.StartsWith("attributes.", StringComparison.Ordinal))
        {
            return "Untrusted fields are not allowed in rule match conditions.";
        }

        return "Unknown path prefix.";
    }

    public static string? ValidateAuditPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "Path is required.";
        }

        if (ExactRulePaths.Contains(path) || TryParseTrustedPath(path, out _))
        {
            return null;
        }

        if (path.StartsWith("request.attributes.", StringComparison.Ordinal))
        {
            return path.Length > "request.attributes.".Length ? null : "Request attribute key is required.";
        }

        if (path.StartsWith("subject.attributes.", StringComparison.Ordinal))
        {
            return path.Length > "subject.attributes.".Length ? null : "Subject attribute key is required.";
        }

        if (path.StartsWith("resource.attributes.", StringComparison.Ordinal))
        {
            return path.Length > "resource.attributes.".Length ? null : "Resource attribute key is required.";
        }

        if (path.StartsWith("context.", StringComparison.Ordinal))
        {
            return path.Length > "context.".Length ? null : "Context key is required.";
        }

        return "Unknown path prefix.";
    }

    public static bool TryParseTrustedPath(string path, out TrustedPath trustedPath)
    {
        trustedPath = default;
        if (!path.StartsWith("trusted.", StringComparison.Ordinal))
        {
            return false;
        }

        var remainder = path["trusted.".Length..];
        var parts = remainder.Split('.', StringSplitOptions.None);
        if (parts.Length is < 1 or > 2)
        {
            return false;
        }

        var key = parts[0];
        if (!IsTrustedSignalKey(key))
        {
            return false;
        }

        var field = parts.Length == 1 ? "value" : parts[1];
        if (field is not ("value" or "issuer" or "version"))
        {
            return false;
        }

        trustedPath = new TrustedPath(key, field, path);
        return true;
    }
}

internal readonly record struct TrustedPath(string Key, string Field, string Path);

internal static class WildcardMatcher
{
    public static string? ValidatePattern(string pattern)
    {
        var count = pattern.Count(c => c == '*');
        if (count == 0)
        {
            return null;
        }

        if (count > 2)
        {
            return "More than two '*' characters is not allowed.";
        }

        if (pattern == "**")
        {
            return "Literal '**' is not allowed.";
        }

        if (count == 1)
        {
            if (pattern == "*")
            {
                return null;
            }

            if (pattern.StartsWith('*') || pattern.EndsWith('*'))
            {
                return null;
            }

            return "Single '*' is valid only as prefix, suffix, or the full value.";
        }

        if (pattern.StartsWith('*') && pattern.EndsWith('*') && pattern.Length > 2)
        {
            return null;
        }

        return "Two '*' characters are valid only as '*contains*'.";
    }

    public static bool IsMatch(string expected, string actual)
    {
        var count = expected.Count(c => c == '*');
        if (count == 0)
        {
            return string.Equals(expected, actual, StringComparison.Ordinal);
        }

        if (expected == "*")
        {
            return true;
        }

        if (count == 1 && expected.StartsWith('*'))
        {
            return actual.EndsWith(expected[1..], StringComparison.Ordinal);
        }

        if (count == 1 && expected.EndsWith('*'))
        {
            return actual.StartsWith(expected[..^1], StringComparison.Ordinal);
        }

        if (count == 2 && expected.StartsWith('*') && expected.EndsWith('*'))
        {
            return actual.Contains(expected[1..^1], StringComparison.Ordinal);
        }

        return false;
    }
}
