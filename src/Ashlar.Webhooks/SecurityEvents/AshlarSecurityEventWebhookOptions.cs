namespace Ashlar.Webhooks.SecurityEvents;

using System.Net;

/// <summary>
/// Defines the network destinations allowed for security event webhook delivery.
/// </summary>
public enum AshlarSecurityEventWebhookDestinationPolicy
{
    /// <summary>
    /// Allows only public internet destinations. The well-known and local-use NAT64 prefixes are blocked,
    /// and configured network-specific NAT64 prefixes are classified by their embedded IPv4 destination.
    /// </summary>
    PublicInternetOnly = 0,

    /// <summary>
    /// Allows private network destinations while continuing to block loopback, link-local, multicast,
    /// unspecified, and special-use destinations, including IPv4 destinations embedded in NAT64 addresses.
    /// </summary>
    AllowPrivateNetworks = 1
}

/// <summary>
/// Configures security event webhook endpoints and delivery settings.
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
    /// Gets the RFC 6052 network-specific NAT64 prefixes used by the deployment. Prefix lengths must be
    /// <c>/32</c>, <c>/40</c>, <c>/48</c>, <c>/56</c>, <c>/64</c>, or <c>/96</c>.
    /// For <c>/96</c> prefixes, bits 64 through 71 must be zero as required by RFC 6052.
    /// The well-known <c>64:ff9b::/96</c> and local-use <c>64:ff9b:1::/48</c> prefixes are always handled.
    /// </summary>
    public IList<IPNetwork> Nat64Prefixes { get; } = [];

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
            && options.Nat64Prefixes.All(AshlarSecurityEventWebhookDestinationValidator.IsValidNat64Prefix)
            && options.Endpoints.All(endpoint => AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint, options.DestinationPolicy, options.Nat64Prefixes))
            && options.Endpoints.Select(endpoint => endpoint.Name).Distinct(StringComparer.Ordinal).Count() == options.Endpoints.Count;
    }
}
