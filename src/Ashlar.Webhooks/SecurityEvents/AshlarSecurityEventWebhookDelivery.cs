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
    /// <param name="headers">The final safe headers to send with the webhook request.</param>
    /// <param name="payload">The safe webhook payload.</param>
    public AshlarSecurityEventWebhookDelivery(
        string endpointName,
        Uri uri,
        TimeSpan timeout,
        IReadOnlyDictionary<string, string> headers,
        AshlarSecurityEventWebhookPayload payload)
        : this(endpointName, uri, timeout, headers, payload, AshlarSecurityEventWebhookPayloadSerializer.Serialize(payload))
    {
    }

    internal AshlarSecurityEventWebhookDelivery(
        string endpointName,
        Uri uri,
        TimeSpan timeout,
        IReadOnlyDictionary<string, string> headers,
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
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(payload);
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            payload.EventType,
            $"{nameof(payload)}.{nameof(payload.EventType)}",
            "Event type is required.",
            "Event type must not contain line breaks.");
        AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
            payload.Outcome,
            $"{nameof(payload)}.{nameof(payload.Outcome)}",
            "Outcome is required.",
            "Outcome must not contain line breaks.");

        if (body.IsEmpty)
        {
            throw new ArgumentException("Webhook body must not be empty.", nameof(body));
        }

        foreach (var header in headers)
        {
            AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
                header.Key,
                nameof(headers),
                "Header names are required.",
                "Header names must not contain line breaks.");
            AshlarSecurityEventWebhookHeaderValues.ThrowIfRequiredUnsafe(
                header.Value,
                nameof(headers),
                "Header values are required.",
                "Header values must not contain line breaks.");
        }

        EndpointName = endpointName;
        Uri = uri;
        Timeout = timeout;
        Headers = headers;
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
    /// Gets the final safe headers to send with the webhook request.
    /// </summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>
    /// Gets the safe webhook payload.
    /// </summary>
    public AshlarSecurityEventWebhookPayload Payload { get; }

    /// <summary>
    /// Gets the serialized safe webhook body.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }
}
