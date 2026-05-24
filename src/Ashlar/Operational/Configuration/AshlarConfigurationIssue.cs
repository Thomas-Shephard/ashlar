namespace Ashlar.Operational.Configuration;

/// <summary>
/// Represents one Ashlar configuration validation finding.
/// </summary>
/// <param name="Code">A stable issue code suitable for logs and deployment checks.</param>
/// <param name="Severity">The issue severity.</param>
/// <param name="Message">A short, non-secret description of the finding.</param>
/// <param name="Recommendation">Recommended remediation or review guidance.</param>
/// <param name="Component">The Ashlar component affected by the finding.</param>
public sealed record AshlarConfigurationIssue(
    string Code,
    AshlarConfigurationIssueSeverity Severity,
    string Message,
    string Recommendation,
    string Component);
