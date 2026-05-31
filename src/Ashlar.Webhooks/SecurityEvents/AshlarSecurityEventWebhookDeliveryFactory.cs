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

        if (!IsSafeEventType(securityEvent.EventType))
        {
            return [];
        }

        if (!TryGetSafeOutcome(securityEvent.Outcome, out var outcome))
        {
            return [];
        }

        var activeEndpoints = _options.Endpoints
            .Where(endpoint => ShouldSend(endpoint, securityEvent.EventType, outcome))
            .ToList();

        if (activeEndpoints.Count == 0)
        {
            return [];
        }

        var payload = CreatePayload(securityEvent, outcome);
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
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            payload.EventType,
            $"{nameof(payload)}.{nameof(payload.EventType)}",
            "Event type is required.",
            "Event type must not contain line breaks.");
        var outcome = GetRequiredSafeHeaderValue(
            payload.Outcome,
            $"{nameof(payload)}.{nameof(payload.Outcome)}",
            "Outcome is required.",
            "Outcome must not contain line breaks.");

        var uri = GetEndpointUri(endpoint);

        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["X-Ashlar-Event-Id"] = payload.Id.ToString("D"),
            ["X-Ashlar-Event-Type"] = payload.EventType,
            ["X-Ashlar-Event-Outcome"] = outcome,
            ["X-Ashlar-Webhook-Endpoint"] = endpoint.Name,
            [AshlarSecurityEventWebhookSignature.EventTimestampHeaderName] = payload.OccurredAt.ToString("O")
        };

        AddSigningHeaders(headers, new AshlarSecurityEventWebhookSigningRequest
        {
            EndpointName = endpoint.Name,
            SharedSecret = endpoint.SharedSecret,
            AllowUnsigned = endpoint.AllowUnsigned,
            EventId = payload.Id,
            OccurredAt = payload.OccurredAt,
            Uri = uri,
            Body = body.ToArray(),
            SignatureTimestamp = signatureTimestamp
        });

        return headers;
    }

    private static string GetRequiredSafeHeaderValue(
        string? value,
        string paramName,
        string requiredMessage,
        string unsafeMessage)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(requiredMessage, paramName);
        }

        if (!AshlarSecurityEventWebhookHeaderValues.IsSafe(value))
        {
            throw new ArgumentException(unsafeMessage, paramName);
        }

        return value;
    }

    internal static void AddSigningHeaders(
        IDictionary<string, string> headers,
        AshlarSecurityEventWebhookSigningRequest request)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Uri);
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            request.EndpointName,
            $"{nameof(request)}.{nameof(request.EndpointName)}",
            "Endpoint name is required.",
            "Endpoint name must not contain line breaks.");
        RemoveHeader(headers, AshlarSecurityEventWebhookSignature.SignatureHeaderName);
        RemoveHeader(headers, AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName);

        if (string.IsNullOrWhiteSpace(request.SharedSecret))
        {
            if (!request.AllowUnsigned)
            {
                throw new InvalidOperationException("Ashlar security event webhook endpoint is missing a shared secret.");
            }

            return;
        }

        headers[AshlarSecurityEventWebhookSignature.SignatureTimestampHeaderName] =
            AshlarSecurityEventWebhookSignature.FormatTimestamp(request.SignatureTimestamp);
        headers[AshlarSecurityEventWebhookSignature.SignatureHeaderName] =
            AshlarSecurityEventWebhookSignature.CreateSignature(
                request.SharedSecret,
                request.Body.Span,
                request.SignatureTimestamp,
                request.OccurredAt,
                request.EventId,
                request.EndpointName,
                AshlarSecurityEventWebhookSignature.CreateCanonicalDestination(request.Uri));
    }

    private static void RemoveHeader(IDictionary<string, string> headers, string headerName)
    {
        var keysToRemove = headers.Keys
            .Where(key => string.Equals(key, headerName, StringComparison.OrdinalIgnoreCase))
            .ToList();

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

        return CreatePayload(
            securityEvent,
            GetRequiredSafeHeaderValue(
                securityEvent.Outcome,
                $"{nameof(securityEvent)}.{nameof(securityEvent.Outcome)}",
                "Outcome is required.",
                "Outcome must not contain line breaks."));
    }

    private static AshlarSecurityEventWebhookPayload CreatePayload(AshlarSecurityEvent securityEvent, string outcome)
    {
        return new AshlarSecurityEventWebhookPayload
        {
            Id = securityEvent.Id,
            EventType = securityEvent.EventType,
            OccurredAt = securityEvent.OccurredAt,
            Outcome = outcome,
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

    private static bool ShouldSend(AshlarSecurityEventWebhookEndpointOptions endpoint, string eventType, string outcome)
    {
        return endpoint.Enabled
            && (endpoint.EventTypes.Count == 0 || endpoint.EventTypes.Contains(eventType))
            && (endpoint.Outcomes.Count == 0 || endpoint.Outcomes.Contains(outcome));
    }

    private static bool IsSafeEventType(string? eventType)
    {
        return !string.IsNullOrWhiteSpace(eventType) && AshlarSecurityEventWebhookHeaderValues.IsSafe(eventType);
    }

    private static bool TryGetSafeOutcome(string? value, out string outcome)
    {
        if (string.IsNullOrWhiteSpace(value) || !AshlarSecurityEventWebhookHeaderValues.IsSafe(value))
        {
            outcome = string.Empty;
            return false;
        }

        outcome = value;
        return true;
    }

    private static Uri GetEndpointUri(AshlarSecurityEventWebhookEndpointOptions endpoint)
    {
        return endpoint.Uri ?? throw new InvalidOperationException("Active webhook endpoint is missing a URI.");
    }
}

/// <summary>
/// Groups inputs used to sign an Ashlar security event webhook request.
/// </summary>
internal sealed class AshlarSecurityEventWebhookSigningRequest
{
    /// <summary>
    /// Gets the endpoint name or identity.
    /// </summary>
    public required string EndpointName { get; init; }

    /// <summary>
    /// Gets the shared secret.
    /// </summary>
    public string? SharedSecret { get; init; }

    /// <summary>
    /// Gets a value indicating whether unsigned delivery is explicitly allowed.
    /// </summary>
    public bool AllowUnsigned { get; init; }

    /// <summary>
    /// Gets the security event identifier.
    /// </summary>
    public Guid EventId { get; init; }

    /// <summary>
    /// Gets the security event occurrence timestamp.
    /// </summary>
    public DateTimeOffset OccurredAt { get; init; }

    /// <summary>
    /// Gets the destination URI.
    /// </summary>
    public required Uri Uri { get; init; }

    /// <summary>
    /// Gets the raw request body bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    /// <summary>
    /// Gets the signature timestamp.
    /// </summary>
    public DateTimeOffset SignatureTimestamp { get; init; }
}
