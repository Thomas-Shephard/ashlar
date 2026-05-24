namespace Ashlar.Operational.Configuration;

/// <summary>
/// Represents the aggregate result of Ashlar configuration validation.
/// </summary>
public sealed class AshlarConfigurationValidationResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarConfigurationValidationResult"/> class.
    /// </summary>
    /// <param name="issues">The validation issues that were found.</param>
    public AshlarConfigurationValidationResult(IEnumerable<AshlarConfigurationIssue> issues)
    {
        ArgumentNullException.ThrowIfNull(issues);

        Issues = issues.ToArray();
        HasErrors = Issues.Any(issue => issue.Severity == AshlarConfigurationIssueSeverity.Error);
        HasWarnings = Issues.Any(issue => issue.Severity == AshlarConfigurationIssueSeverity.Warning);
        IsValid = !HasErrors;
    }

    /// <summary>
    /// Gets the validation issues that were found.
    /// </summary>
    public IReadOnlyList<AshlarConfigurationIssue> Issues { get; }

    /// <summary>
    /// Gets a value indicating whether any error issues were found.
    /// </summary>
    public bool HasErrors { get; }

    /// <summary>
    /// Gets a value indicating whether any warning issues were found.
    /// </summary>
    public bool HasWarnings { get; }

    /// <summary>
    /// Gets a value indicating whether the configuration has no error issues.
    /// </summary>
    public bool IsValid { get; }
}
