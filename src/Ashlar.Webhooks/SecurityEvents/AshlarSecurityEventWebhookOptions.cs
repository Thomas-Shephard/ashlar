namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Defines the network destinations allowed for security event webhook delivery.
/// </summary>
public enum AshlarSecurityEventWebhookDestinationPolicy
{
    /// <summary>
    /// Allows only public internet destinations.
    /// </summary>
    PublicInternetOnly = 0,

    /// <summary>
    /// Allows private network destinations while continuing to block loopback, link-local, multicast, and unspecified destinations.
    /// </summary>
    AllowPrivateNetworks = 1
}

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
    /// Gets or sets the destination policy for webhook endpoint validation and dispatch.
    /// </summary>
    public AshlarSecurityEventWebhookDestinationPolicy DestinationPolicy { get; set; } =
        AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly;

    /// <summary>
    /// Validates webhook options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(AshlarSecurityEventWebhookOptions? options)
    {
        return options is not null
            && options.Timeout > TimeSpan.Zero
            && Enum.IsDefined(options.DestinationPolicy)
            && options.Endpoints.All(endpoint => AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint, options.DestinationPolicy));
    }
}
