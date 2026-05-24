using Ashlar.Auditing;
using Ashlar.Identity.Models.Authentication;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Creates prepared Ashlar security event webhook deliveries from configured endpoints.
/// </summary>
public sealed class AshlarSecurityEventWebhookDeliveryFactory
{
    private readonly AshlarSecurityEventWebhookOptions _options;

    /// <summary>
    /// Initializes a new instance of the delivery factory class.
    /// </summary>
    /// <param name="options">The webhook options.</param>
    public AshlarSecurityEventWebhookDeliveryFactory(IOptions<AshlarSecurityEventWebhookOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
    }

    /// <summary>
    /// Creates prepared deliveries for endpoints that should receive the event.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <returns>The prepared deliveries.</returns>
    public IReadOnlyList<AshlarSecurityEventWebhookDelivery> CreateDeliveries(AshlarSecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        var activeEndpoints = _options.Endpoints
            .Where(endpoint => ShouldSend(endpoint, securityEvent.EventType))
            .ToList();

        if (activeEndpoints.Count == 0)
        {
            return [];
        }

        var payload = CreatePayload(securityEvent);
        var body = AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload);
        return activeEndpoints
            .Select(endpoint => new AshlarSecurityEventWebhookDelivery(
                endpoint.Name,
                GetEndpointUri(endpoint),
                endpoint.Timeout ?? _options.Timeout,
                endpoint.SharedSecret,
                payload,
                body))
            .ToArray();
    }

    /// <summary>
    /// Creates the safe webhook payload for an Ashlar security event.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <returns>The safe webhook payload.</returns>
    public static AshlarSecurityEventWebhookPayload CreatePayload(AshlarSecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        return new AshlarSecurityEventWebhookPayload
        {
            Id = securityEvent.Id,
            EventType = securityEvent.EventType,
            OccurredAt = securityEvent.OccurredAt,
            Outcome = securityEvent.Outcome,
            FailureReason = securityEvent.FailureReason,
            UserId = securityEvent.UserId,
            TenantId = securityEvent.TenantId,
            ActorUserId = securityEvent.ActorUserId,
            SessionId = securityEvent.SessionId,
            ProviderType = AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
            ProviderName = securityEvent.Provider?.Name,
            CorrelationId = securityEvent.CorrelationId
        };
    }

    private static bool ShouldSend(AshlarSecurityEventWebhookEndpointOptions endpoint, string eventType)
    {
        return endpoint.Enabled && (endpoint.EventTypes.Count == 0 || endpoint.EventTypes.Contains(eventType));
    }

    private static Uri GetEndpointUri(AshlarSecurityEventWebhookEndpointOptions endpoint)
    {
        return endpoint.Uri ?? throw new InvalidOperationException("Active webhook endpoint is missing a URI.");
    }
}
