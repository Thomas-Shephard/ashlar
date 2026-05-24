namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Represents a prepared security event webhook delivery for one endpoint.
/// </summary>
public sealed record AshlarSecurityEventWebhookDelivery
{
    /// <summary>
    /// Initializes a new prepared webhook delivery.
    /// </summary>
    /// <param name="endpointName">The endpoint display name used in safe logs and headers.</param>
    /// <param name="uri">The endpoint URI.</param>
    /// <param name="timeout">The per-request timeout.</param>
    /// <param name="sharedSecret">The optional shared secret used for best-effort signing.</param>
    /// <param name="payload">The safe webhook payload.</param>
    public AshlarSecurityEventWebhookDelivery(
        string endpointName,
        Uri uri,
        TimeSpan timeout,
        string? sharedSecret,
        AshlarSecurityEventWebhookPayload payload)
        : this(endpointName, uri, timeout, sharedSecret, payload, AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload))
    {
    }

    internal AshlarSecurityEventWebhookDelivery(
        string endpointName,
        Uri uri,
        TimeSpan timeout,
        string? sharedSecret,
        AshlarSecurityEventWebhookPayload payload,
        ReadOnlyMemory<byte> body)
    {
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            endpointName,
            nameof(endpointName),
            "Endpoint name is required.",
            "Endpoint name must not contain line breaks.");
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        ArgumentNullException.ThrowIfNull(payload);
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            payload.EventType,
            $"{nameof(payload)}.{nameof(payload.EventType)}",
            "Event type is required.",
            "Event type must not contain line breaks.");

        if (sharedSecret is not null && string.IsNullOrWhiteSpace(sharedSecret))
        {
            throw new ArgumentException("Shared secret must not be blank.", nameof(sharedSecret));
        }

        if (body.IsEmpty)
        {
            throw new ArgumentException("Webhook body must not be empty.", nameof(body));
        }

        EndpointName = endpointName;
        Uri = uri;
        Timeout = timeout;
        SharedSecret = sharedSecret;
        Payload = payload;
        Body = body;
    }

    /// <summary>
    /// Gets the endpoint display name used in safe logs and headers.
    /// </summary>
    public string EndpointName { get; }

    /// <summary>
    /// Gets the endpoint URI.
    /// </summary>
    public Uri Uri { get; }

    /// <summary>
    /// Gets the per-request timeout.
    /// </summary>
    public TimeSpan Timeout { get; }

    /// <summary>
    /// Gets the optional shared secret used for best-effort signing.
    /// </summary>
    /// <remarks>
    /// Durable providers should avoid storing this plaintext value directly; a later provider slice should
    /// either persist enqueue-time signature material or introduce a key identifier model.
    /// </remarks>
    public string? SharedSecret { get; }

    /// <summary>
    /// Gets the safe webhook payload.
    /// </summary>
    public AshlarSecurityEventWebhookPayload Payload { get; }

    /// <summary>
    /// Gets the serialized safe webhook body.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }
}
