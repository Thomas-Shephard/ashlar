namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Configures one Ashlar security event webhook endpoint.
/// </summary>
public sealed class AshlarSecurityEventWebhookEndpointOptions
{
    /// <summary>
    /// Gets or sets the endpoint display name used in safe logs and headers.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the absolute HTTPS endpoint URI.
    /// </summary>
    public Uri? Uri { get; set; }

    /// <summary>
    /// Gets or sets an optional shared secret used to sign request bodies. When supplied, the secret must be at least
    /// <see cref="AshlarSecurityEventWebhookSignature.MinimumSharedSecretByteLength"/> UTF-8 bytes.
    /// </summary>
    public string? SharedSecret { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this endpoint may receive unsigned webhooks when
    /// <see cref="SharedSecret"/> is <see langword="null"/>.
    /// </summary>
    public bool AllowUnsigned { get; set; }

    /// <summary>
    /// Gets the optional event type allow-list.
    /// </summary>
    public ISet<string> EventTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the optional outcome allow-list.
    /// </summary>
    public ISet<string> Outcomes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the optional per-request timeout.
    /// </summary>
    public TimeSpan? Timeout { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether delivery to the endpoint is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Validates endpoint options.
    /// </summary>
    /// <param name="endpoint">The endpoint options.</param>
    /// <returns><see langword="true" /> when the endpoint is valid.</returns>
    public static bool Validate(AshlarSecurityEventWebhookEndpointOptions? endpoint)
    {
        return Validate(endpoint, AshlarSecurityEventWebhookDestinationPolicy.PublicInternetOnly);
    }

    internal static bool Validate(
        AshlarSecurityEventWebhookEndpointOptions? endpoint,
        AshlarSecurityEventWebhookDestinationPolicy destinationPolicy,
        IEnumerable<System.Net.IPNetwork>? nat64Prefixes = null)
    {
        return endpoint is not null
            && !string.IsNullOrWhiteSpace(endpoint.Name)
            && AshlarSecurityEventWebhookHeaderValues.IsSafe(endpoint.Name)
            && AshlarSecurityEventWebhookDestinationValidator.ValidateUri(endpoint.Uri, destinationPolicy, nat64Prefixes).IsValid
            && AshlarSecurityEventWebhookSignature.IsSigningConfigurationValid(
                endpoint.SharedSecret,
                endpoint.AllowUnsigned)
            && (!endpoint.Timeout.HasValue || endpoint.Timeout.Value > TimeSpan.Zero)
            && endpoint.EventTypes.All(eventType =>
                !string.IsNullOrWhiteSpace(eventType) && AshlarSecurityEventWebhookHeaderValues.IsSafe(eventType))
            && endpoint.Outcomes.All(outcome =>
                !string.IsNullOrWhiteSpace(outcome) && AshlarSecurityEventWebhookHeaderValues.IsSafe(outcome));
    }
}
