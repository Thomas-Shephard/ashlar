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
    /// Gets or sets an optional shared secret used to sign request bodies.
    /// </summary>
    public string? SharedSecret { get; set; }

    /// <summary>
    /// Gets the optional event type allow-list.
    /// </summary>
    public ISet<string> EventTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
        return endpoint is not null
            && !string.IsNullOrWhiteSpace(endpoint.Name)
            && IsHeaderValueSafe(endpoint.Name)
            && endpoint.Uri is { IsAbsoluteUri: true }
            && endpoint.Uri.Scheme == Uri.UriSchemeHttps
            && (endpoint.SharedSecret is null || !string.IsNullOrWhiteSpace(endpoint.SharedSecret))
            && (!endpoint.Timeout.HasValue || endpoint.Timeout.Value > TimeSpan.Zero)
            && endpoint.EventTypes.All(eventType => !string.IsNullOrWhiteSpace(eventType));
    }

    private static bool IsHeaderValueSafe(string value)
    {
        return !value.Any(character => character is '\r' or '\n');
    }
}
