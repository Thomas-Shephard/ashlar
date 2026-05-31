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
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the delivery factory class.
    /// </summary>
    /// <param name="options">The webhook options.</param>
    /// <param name="timeProvider">The time provider.</param>
    public AshlarSecurityEventWebhookDeliveryFactory(
        IOptions<AshlarSecurityEventWebhookOptions> options,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _timeProvider = timeProvider ?? TimeProvider.System;
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
        var signatureTimestamp = _timeProvider.GetUtcNow();
        return activeEndpoints
            .Select(endpoint => new AshlarSecurityEventWebhookDelivery(
                endpoint.Name,
                GetEndpointUri(endpoint),
                endpoint.Timeout ?? _options.Timeout,
                CreateHeaders(endpoint, payload, body, signatureTimestamp),
                payload,
                body))
            .ToArray();
    }

    /// <summary>
    /// Creates the final safe headers for a prepared webhook delivery.
    /// </summary>
    /// <param name="endpoint">The endpoint options.</param>
    /// <param name="payload">The payload value.</param>
    /// <param name="body">The serialized body bytes used for signing.</param>
    /// <param name="signatureTimestamp">The signature timestamp.</param>
    /// <returns>The final headers.</returns>
    public static IReadOnlyDictionary<string, string> CreateHeaders(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        AshlarSecurityEventWebhookPayload payload,
        ReadOnlySpan<byte> body,
        DateTimeOffset signatureTimestamp)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            endpoint.Name,
            $"{nameof(endpoint)}.{nameof(endpoint.Name)}",
            "Endpoint name is required.",
            "Endpoint name must not contain line breaks.");
        ArgumentNullException.ThrowIfNull(payload);
        var uri = GetEndpointUri(endpoint);

        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["X-Ashlar-Event-Id"] = payload.Id.ToString("D"),
            ["X-Ashlar-Event-Type"] = payload.EventType,
            ["X-Ashlar-Webhook-Endpoint"] = endpoint.Name,
            [AshlarSecurityEventWebhookSignature.EventTimestampHeaderName] = payload.OccurredAt.ToString("O")
        };

        AddSigningHeaders(headers, endpoint.Name, endpoint.SharedSecret, endpoint.AllowUnsigned, payload.Id, payload.OccurredAt, uri, body, signatureTimestamp);

        return headers;
    }

    internal static void AddSigningHeaders(
        IDictionary<string, string> headers,
        string endpointName,
        string? sharedSecret,
        bool allowUnsigned,
        Guid eventId,
        DateTimeOffset occurredAt,
        Uri uri,
        ReadOnlySpan<byte> body,
        DateTimeOffset signatureTimestamp)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(uri);
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            endpointName,
            nameof(endpointName),
            "Endpoint name is required.",
            "Endpoint name must not contain line breaks.");
        RemoveHeader(headers, AshlarSecurityEventWebhookSignature.SignatureHeaderName);
        RemoveHeader(headers, AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName);

        if (string.IsNullOrWhiteSpace(sharedSecret))
        {
            if (!allowUnsigned)
            {
                throw new InvalidOperationException("Ashlar security event webhook endpoint is missing a shared secret.");
            }

            return;
        }

        headers[AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName] =
            AshlarSecurityEventWebhookSignature.FormatTimestamp(signatureTimestamp);
        headers[AshlarSecurityEventWebhookSignature.SignatureHeaderName] =
            AshlarSecurityEventWebhookSignature.CreateSignature(
                sharedSecret,
                body,
                signatureTimestamp,
                occurredAt,
                eventId,
                endpointName,
                AshlarSecurityEventWebhookSignature.CreateCanonicalDestination(uri));
    }

    private static void RemoveHeader(IDictionary<string, string> headers, string headerName)
    {
        var keysToRemove = new List<string>();
        foreach (var key in headers.Keys)
        {
            if (string.Equals(key, headerName, StringComparison.OrdinalIgnoreCase))
            {
                keysToRemove.Add(key);
            }
        }

        foreach (var key in keysToRemove)
        {
            headers.Remove(key);
        }
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
