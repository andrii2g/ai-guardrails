namespace A2G.AIGuardrails.Core;

public sealed class GuardEngine : IGuardEngine
{
    private readonly GuardPolicy _policy;
    private readonly IAuditSink? _auditSink;
    private readonly AuditFailureMode _auditFailureMode;
    private readonly IClock _clock;

    public GuardEngine(
        GuardPolicy policy,
        IAuditSink? auditSink = null,
        AuditFailureMode auditFailureMode = AuditFailureMode.FailClosed,
        IClock? clock = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _auditSink = auditSink;
        _auditFailureMode = auditFailureMode;
        _clock = clock ?? new SystemClock();

        var policyErrors = ValidateConstructedPolicy(policy);
        if (policyErrors.Count > 0)
        {
            throw new ArgumentException(string.Join(Environment.NewLine, policyErrors), nameof(policy));
        }
    }

    public GuardEvaluationResult Evaluate(GuardRequest request)
    {
        try
        {
            var requestErrors = ValidateRequest(request);
            if (requestErrors.Count > 0)
            {
                return GuardEvaluationResult.InvalidRequest(requestErrors);
            }

            var relevantSignalKeys = DetermineDecisionRelevantTrustedSignalKeys(request);
            var freshnessErrors = ValidateTrustedSignalFreshness(request, relevantSignalKeys);
            if (freshnessErrors.Count > 0)
            {
                return GuardEvaluationResult.InvalidRequest(freshnessErrors);
            }

            var matchedRules = _policy.Rules
                .Where(rule => RuleMatches(rule, request))
                .ToList();

            var winningRules = SelectWinningRules(matchedRules);
            var decision = BuildDecision(winningRules);
            var auditEvent = _policy.Audit.Enabled
                ? BuildAuditEvent(request, winningRules, decision)
                : null;

            if (_policy.Audit.Enabled && _auditSink is not null && auditEvent is not null)
            {
                try
                {
                    _auditSink.Write(auditEvent);
                }
                catch (Exception ex)
                {
                    if (_auditFailureMode == AuditFailureMode.BestEffort)
                    {
                        decision.Diagnostics.Add($"Audit write failed: {ex.Message}");
                        return GuardEvaluationResult.Evaluated(decision, auditEvent);
                    }

                    return GuardEvaluationResult.AuditWriteFailed(
                        decision,
                        auditEvent,
                        new[] { ex.Message });
                }
            }

            return GuardEvaluationResult.Evaluated(decision, auditEvent);
        }
        catch (Exception ex)
        {
            return GuardEvaluationResult.RuntimeError(new[] { ex.Message });
        }
    }

    private List<string> ValidateConstructedPolicy(GuardPolicy policy)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(policy.Id))
        {
            errors.Add("Policy ID is required.");
        }

        if (string.IsNullOrWhiteSpace(policy.Version))
        {
            errors.Add("Policy version is required.");
        }

        if (string.IsNullOrWhiteSpace(policy.DefaultDecision))
        {
            errors.Add("Policy defaultDecision is required.");
        }

        if (policy.TrustedSignals.DefaultMaxAgeSeconds <= 0)
        {
            errors.Add("trustedSignals.defaultMaxAgeSeconds must be greater than 0.");
        }

        foreach (var key in policy.Rules.SelectMany(rule => rule.Match.Keys))
        {
            var error = PathGrammar.ValidateRuleMatchPath(key);
            if (error is not null)
            {
                errors.Add($"Invalid rule match path '{key}': {error}");
            }
        }

        return errors;
    }

    private List<string> ValidateRequest(GuardRequest? request)
    {
        var errors = new List<string>();
        if (request is null)
        {
            errors.Add("Request is required.");
            return errors;
        }

        if (request.Subject is null)
        {
            errors.Add("Subject is required.");
        }
        else
        {
            ValidateRequiredScalar(request.Subject.Type, "Subject.Type", errors);
            ValidateRequiredScalar(request.Subject.Id, "Subject.Id", errors);
            ValidateStringDictionary(request.Subject.Attributes, "Subject.Attributes", errors);
        }

        ValidateRequiredScalar(request.Action, "Action", errors);

        if (request.Resource is null)
        {
            errors.Add("Resource is required.");
        }
        else
        {
            ValidateRequiredScalar(request.Resource.Type, "Resource.Type", errors);
            ValidateRequiredScalar(request.Resource.Id, "Resource.Id", errors);
            ValidateStringDictionary(request.Resource.Attributes, "Resource.Attributes", errors);
        }

        ValidateStringDictionary(request.Attributes, "Attributes", errors);
        ValidateStringDictionary(request.Context, "Context", errors);
        ValidateTrustedSignals(request.TrustedSignals, errors);

        return errors;
    }

    private HashSet<string> DetermineDecisionRelevantTrustedSignalKeys(GuardRequest request)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var rule in _policy.Rules)
        {
            var trustedConditions = new List<KeyValuePair<string, string>>();
            var nonTrustedConditions = new List<KeyValuePair<string, string>>();

            foreach (var condition in rule.Match)
            {
                if (PathGrammar.TryParseTrustedPath(condition.Key, out _))
                {
                    trustedConditions.Add(condition);
                }
                else
                {
                    nonTrustedConditions.Add(condition);
                }
            }

            var nonTrustedMatches = nonTrustedConditions.All(condition => ConditionMatches(request, condition.Key, condition.Value));
            if (!nonTrustedMatches)
            {
                continue;
            }

            foreach (var condition in trustedConditions)
            {
                _ = PathGrammar.TryParseTrustedPath(condition.Key, out var trustedPath);
                keys.Add(trustedPath.Key);
            }
        }

        return keys;
    }

    private List<string> ValidateTrustedSignalFreshness(GuardRequest request, HashSet<string> relevantSignalKeys)
    {
        var errors = new List<string>();
        var now = _clock.UtcNow;

        foreach (var key in relevantSignalKeys)
        {
            if (!request.TrustedSignals.TryGetValue(key, out var signal))
            {
                continue;
            }

            if (!DateTimeOffset.TryParse(signal.IssuedAtUtc, out var issuedAt))
            {
                continue;
            }

            var maxAge = _policy.TrustedSignals.MaxAgeSecondsByKey.TryGetValue(key, out var perKeyAge)
                ? perKeyAge
                : _policy.TrustedSignals.DefaultMaxAgeSeconds;

            if (issuedAt - now > TimeSpan.FromSeconds(60))
            {
                errors.Add($"Trusted signal '{key}' has a future timestamp beyond the allowed 60-second skew.");
                continue;
            }

            if (now - issuedAt > TimeSpan.FromSeconds(maxAge))
            {
                errors.Add($"Trusted signal '{key}' is stale. IssuedAtUtc is older than max age {maxAge} seconds.");
            }
        }

        return errors;
    }

    private bool RuleMatches(PolicyRule rule, GuardRequest request)
        => rule.Match.All(condition => ConditionMatches(request, condition.Key, condition.Value));

    private bool ConditionMatches(GuardRequest request, string path, string expected)
    {
        if (!TryResolveRuleValue(request, path, out var actual))
        {
            return false;
        }

        return WildcardMatcher.IsMatch(expected, actual);
    }

    private List<PolicyRule> SelectWinningRules(List<PolicyRule> matchedRules)
    {
        if (matchedRules.Count == 0)
        {
            return new List<PolicyRule>();
        }

        var targetEffect = matchedRules.Any(r => r.Effect == "deny")
            ? "deny"
            : matchedRules.Any(r => r.Effect == "review")
                ? "review"
                : "allow";

        return matchedRules
            .Where(rule => rule.Effect == targetEffect)
            .OrderBy(rule => rule.Id, StringComparer.Ordinal)
            .ToList();
    }

    private GuardDecision BuildDecision(List<PolicyRule> winningRules)
    {
        if (winningRules.Count == 0)
        {
            var defaultDecision = _policy.DefaultDecision switch
            {
                "allow" => DecisionType.Allow,
                "review" => DecisionType.RequireApproval,
                _ => DecisionType.Deny
            };

            var defaultRisk = _policy.DefaultDecision switch
            {
                "allow" => RiskLevel.Low,
                "review" => RiskLevel.Medium,
                _ => RiskLevel.High
            };

            return new GuardDecision
            {
                Decision = defaultDecision,
                Risk = defaultRisk,
                Reason = $"No policy rule matched. Applied default decision '{_policy.DefaultDecision}'."
            };
        }

        var effect = winningRules[0].Effect;
        var decisionType = effect switch
        {
            "allow" => DecisionType.Allow,
            "review" => DecisionType.RequireApproval,
            _ => DecisionType.Deny
        };

        var matchedRuleReasons = winningRules
            .Select(rule => new MatchedRuleReason
            {
                RuleId = rule.Id,
                Effect = rule.Effect,
                Risk = ParseRisk(rule.Risk),
                Reason = BuildRuleReason(rule)
            })
            .ToList();

        var reason = winningRules.Count == 1
            ? matchedRuleReasons[0].Reason
            : $"Matched {effect} rules: {string.Join(", ", winningRules.Select(rule => rule.Id))}.";

        return new GuardDecision
        {
            Decision = decisionType,
            Risk = matchedRuleReasons.MaxBy(reasonItem => reasonItem.RiskOrder())!.Risk,
            Reason = reason,
            MatchedRules = winningRules.Select(rule => rule.Id).ToList(),
            MatchedRuleReasons = matchedRuleReasons
        };
    }

    private AuditEvent BuildAuditEvent(GuardRequest request, List<PolicyRule> winningRules, GuardDecision decision)
    {
        return new AuditEvent
        {
            EventId = Guid.NewGuid().ToString("N"),
            EvaluatedAtUtc = _clock.UtcNow.ToString("O"),
            CorrelationId = request.CorrelationId,
            PolicyId = _policy.Id,
            PolicyVersion = _policy.Version,
            SubjectType = request.Subject.Type,
            SubjectId = request.Subject.Id,
            Action = request.Action,
            ResourceType = request.Resource.Type,
            ResourceId = request.Resource.Id,
            Decision = decision.Decision,
            Risk = decision.Risk,
            Reason = decision.Reason,
            MatchedRules = decision.MatchedRules.ToList(),
            MatchedTrustedEvidence = BuildMatchedTrustedEvidence(request, winningRules),
            RequestSnapshot = BuildRequestSnapshot(request)
        };
    }

    private List<MatchedTrustedEvidence> BuildMatchedTrustedEvidence(GuardRequest request, List<PolicyRule> winningRules)
    {
        var evidence = new List<MatchedTrustedEvidence>();

        foreach (var rule in winningRules)
        {
            foreach (var condition in rule.Match)
            {
                if (!PathGrammar.TryParseTrustedPath(condition.Key, out var trustedPath))
                {
                    continue;
                }

                if (!request.TrustedSignals.TryGetValue(trustedPath.Key, out var signal))
                {
                    continue;
                }

                if (!TryResolveRuleValue(request, condition.Key, out var actual))
                {
                    continue;
                }

                evidence.Add(new MatchedTrustedEvidence
                {
                    RuleId = rule.Id,
                    Path = condition.Key,
                    SignalKey = trustedPath.Key,
                    Field = trustedPath.Field,
                    Expected = condition.Value,
                    Actual = actual,
                    SignalValue = signal.Value,
                    SignalIssuer = signal.Issuer,
                    SignalVersion = signal.Version,
                    SignalIssuedAtUtc = signal.IssuedAtUtc
                });
            }
        }

        return evidence;
    }

    private Dictionary<string, string> BuildRequestSnapshot(GuardRequest request)
    {
        if (_policy.Audit.IncludeFields.Count == 0)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        var snapshot = new Dictionary<string, string>(StringComparer.Ordinal);
        var redactFields = new HashSet<string>(_policy.Audit.RedactFields, StringComparer.Ordinal);

        foreach (var includeField in _policy.Audit.IncludeFields)
        {
            if (!TryResolveAuditValue(request, includeField, out var actual))
            {
                continue;
            }

            snapshot[includeField] = redactFields.Contains(includeField) ? "[REDACTED]" : actual;
        }

        return snapshot;
    }

    private bool TryResolveRuleValue(GuardRequest request, string path, out string value)
    {
        switch (path)
        {
            case "action":
                value = request.Action;
                return true;
            case "subject.type":
                value = request.Subject.Type;
                return true;
            case "subject.id":
                value = request.Subject.Id;
                return true;
            case "resource.type":
                value = request.Resource.Type;
                return true;
            case "resource.id":
                value = request.Resource.Id;
                return true;
            default:
                if (PathGrammar.TryParseTrustedPath(path, out var trustedPath) &&
                    request.TrustedSignals.TryGetValue(trustedPath.Key, out var signal))
                {
                    value = trustedPath.Field switch
                    {
                        "issuer" => signal.Issuer,
                        "version" => signal.Version ?? string.Empty,
                        _ => signal.Value
                    };
                    return true;
                }

                value = string.Empty;
                return false;
        }
    }

    private bool TryResolveAuditValue(GuardRequest request, string path, out string value)
    {
        if (TryResolveRuleValue(request, path, out value))
        {
            return true;
        }

        if (path.StartsWith("request.attributes.", StringComparison.Ordinal))
        {
            if (request.Attributes.TryGetValue(path["request.attributes.".Length..], out var attributeValue))
            {
                value = attributeValue;
                return true;
            }

            value = string.Empty;
            return false;
        }

        if (path.StartsWith("subject.attributes.", StringComparison.Ordinal))
        {
            if (request.Subject.Attributes.TryGetValue(path["subject.attributes.".Length..], out var subjectValue))
            {
                value = subjectValue;
                return true;
            }

            value = string.Empty;
            return false;
        }

        if (path.StartsWith("resource.attributes.", StringComparison.Ordinal))
        {
            if (request.Resource.Attributes.TryGetValue(path["resource.attributes.".Length..], out var resourceValue))
            {
                value = resourceValue;
                return true;
            }

            value = string.Empty;
            return false;
        }

        if (path.StartsWith("context.", StringComparison.Ordinal))
        {
            if (request.Context.TryGetValue(path["context.".Length..], out var contextValue))
            {
                value = contextValue;
                return true;
            }

            value = string.Empty;
            return false;
        }

        value = string.Empty;
        return false;
    }

    private static void ValidateRequiredScalar(string? value, string name, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"{name} is required.");
        }
    }

    private static void ValidateStringDictionary(Dictionary<string, string>? dictionary, string name, List<string> errors)
    {
        if (dictionary is null)
        {
            errors.Add($"{name} is required.");
            return;
        }

        foreach (var entry in dictionary)
        {
            if (string.IsNullOrWhiteSpace(entry.Key))
            {
                errors.Add($"{name} contains an invalid key.");
            }

            if (entry.Value is null)
            {
                errors.Add($"{name} contains a null value.");
            }
        }
    }

    private static void ValidateTrustedSignals(Dictionary<string, TrustedSignal>? signals, List<string> errors)
    {
        if (signals is null)
        {
            errors.Add("TrustedSignals is required.");
            return;
        }

        foreach (var entry in signals)
        {
            if (string.IsNullOrWhiteSpace(entry.Key))
            {
                errors.Add("TrustedSignals contains an invalid key.");
                continue;
            }

            if (!PathGrammar.IsTrustedSignalKey(entry.Key))
            {
                errors.Add($"TrustedSignals key '{entry.Key}' is invalid.");
            }

            if (entry.Value is null)
            {
                errors.Add($"Trusted signal '{entry.Key}' is null.");
                continue;
            }

            if (entry.Value.Value is null)
            {
                errors.Add($"Trusted signal '{entry.Key}'.Value is required.");
            }

            if (string.IsNullOrWhiteSpace(entry.Value.Issuer))
            {
                errors.Add($"Trusted signal '{entry.Key}'.Issuer is required.");
            }

            if (string.IsNullOrWhiteSpace(entry.Value.IssuedAtUtc) ||
                !DateTimeOffset.TryParse(entry.Value.IssuedAtUtc, out _))
            {
                errors.Add($"Trusted signal '{entry.Key}'.IssuedAtUtc must be a valid ISO-8601 UTC timestamp.");
            }
        }
    }

    private static string BuildRuleReason(PolicyRule rule)
        => string.IsNullOrWhiteSpace(rule.Reason)
            ? $"Matched {rule.Effect} rule '{rule.Id}'."
            : rule.Reason;

    private static RiskLevel ParseRisk(string risk)
        => risk switch
        {
            "high" => RiskLevel.High,
            "medium" => RiskLevel.Medium,
            _ => RiskLevel.Low
        };
}

internal static class RiskOrderingExtensions
{
    public static int RiskOrder(this MatchedRuleReason reason)
        => reason.Risk switch
        {
            RiskLevel.High => 3,
            RiskLevel.Medium => 2,
            _ => 1
        };
}
