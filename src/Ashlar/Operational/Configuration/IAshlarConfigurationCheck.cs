namespace Ashlar.Operational.Configuration;

/// <summary>
/// Validates one provider-neutral or provider-specific Ashlar configuration concern.
/// </summary>
public interface IAshlarConfigurationCheck
{
    /// <summary>
    /// Runs the configuration check.
    /// </summary>
    /// <param name="serviceProvider">The service provider to inspect.</param>
    /// <param name="cancellationToken">The token used to cancel configuration validation.</param>
    /// <returns>The configuration issues found by this check.</returns>
    ValueTask<IReadOnlyList<AshlarConfigurationIssue>> CheckAsync(IServiceProvider serviceProvider, CancellationToken cancellationToken = default);
}
