namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Safe webhook payload for Ashlar security events.
/// </summary>
public sealed class AshlarSecurityEventWebhookPayload
{
    /// <summary>
    /// Gets or sets the event id value.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Gets or sets the event type value.
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// Gets or sets the occurred at value.
    /// </summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>
    /// Gets or sets the outcome value.
    /// </summary>
    public string? Outcome { get; init; }

    /// <summary>
    /// Gets or sets the failure reason value.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Gets or sets the user id value.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Gets or sets the tenant id value.
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>
    /// Gets or sets the actor user id value.
    /// </summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>
    /// Gets or sets the session id value.
    /// </summary>
    public Guid? SessionId { get; init; }

    /// <summary>
    /// Gets or sets the provider type value.
    /// </summary>
    public string? ProviderType { get; init; }

    /// <summary>
    /// Gets or sets the provider name value.
    /// </summary>
    public string? ProviderName { get; init; }

    /// <summary>
    /// Gets or sets the correlation id value.
    /// </summary>
    public string? CorrelationId { get; init; }
}
