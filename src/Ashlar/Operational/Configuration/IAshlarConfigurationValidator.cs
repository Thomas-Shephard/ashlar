namespace Ashlar.Operational.Configuration;

/// <summary>
/// Aggregates registered Ashlar configuration checks.
/// </summary>
public interface IAshlarConfigurationValidator
{
    /// <summary>
    /// Validates the current Ashlar configuration.
    /// </summary>
    /// <param name="cancellationToken">The token used to cancel configuration validation.</param>
    /// <returns>The validation issues and aggregate validity flags for the current configuration.</returns>
    Task<AshlarConfigurationValidationResult> ValidateAsync(CancellationToken cancellationToken = default);
}
