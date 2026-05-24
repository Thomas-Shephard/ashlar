namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Configures best-effort webhook delivery for Ashlar security events.
/// </summary>
public sealed class AshlarSecurityEventWebhookOptions
{
    /// <summary>
    /// Defines the default per-request timeout.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Gets the configured webhook endpoints.
    /// </summary>
    public IList<AshlarSecurityEventWebhookEndpointOptions> Endpoints { get; } = [];

    /// <summary>
    /// Gets or sets the fallback per-request timeout for endpoints without an explicit timeout.
    /// </summary>
    public TimeSpan Timeout { get; set; } = DefaultTimeout;

    /// <summary>
    /// Validates webhook options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(AshlarSecurityEventWebhookOptions? options)
    {
        return options is not null
            && options.Timeout > TimeSpan.Zero
            && options.Endpoints.All(AshlarSecurityEventWebhookEndpointOptions.Validate);
    }
}
