namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Webhook payload for an Ashlar security event.
/// </summary>
/// <remarks>
/// The payload is sent with signed webhook requests and is intended for diagnostics, routing, and idempotent event
/// processing. It does not contain credential secrets, bearer tokens, recovery codes, or raw external-provider
/// tickets.
/// </remarks>
public sealed class AshlarSecurityEventWebhookPayload
{
    /// <summary>
    /// Gets the stable security event identifier for deduplication and idempotent processing.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Gets the Ashlar security event type.
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// Gets the UTC instant when the security event occurred.
    /// </summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>
    /// Gets the display-safe event outcome, such as success or failure.
    /// </summary>
    public required string Outcome { get; init; }

    /// <summary>
    /// Gets the display-safe failure reason when the event represents a failed operation.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Gets the subject user identifier associated with the event, when one is known.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Gets the tenant identifier that scoped the event, when one is known.
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>
    /// Gets the administrator or acting user identifier when the event was performed on behalf of another user.
    /// </summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>
    /// Gets the authentication session identifier associated with the event, when one is known.
    /// </summary>
    public Guid? SessionId { get; init; }

    /// <summary>
    /// Gets the credential provider type associated with the event, when applicable.
    /// </summary>
    public string? ProviderType { get; init; }

    /// <summary>
    /// Gets the configured credential provider name associated with the event, when applicable.
    /// </summary>
    public string? ProviderName { get; init; }

    /// <summary>
    /// Gets the host-provided correlation identifier used to connect the event to request diagnostics.
    /// </summary>
    public string? CorrelationId { get; init; }
}
