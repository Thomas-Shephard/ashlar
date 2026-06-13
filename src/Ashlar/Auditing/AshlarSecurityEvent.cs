namespace Ashlar.Auditing;

/// <summary>
/// Structured provider-neutral event for security-sensitive Ashlar operations.
/// </summary>
public sealed record AshlarSecurityEvent
{
    /// <summary>
    /// Unique identifier for this specific audit event instance.
    /// </summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Stable event type identifier, such as a value from <see cref="AshlarSecurityEventTypes" />.
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// Time the event occurred.
    /// </summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>
    /// User affected by the security event, when known.
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Tenant associated with the event, or <see langword="null" /> for global events.
    /// </summary>
    public Guid? TenantId { get; init; }

    /// <summary>
    /// User that initiated the operation, when different from or more specific than <see cref="UserId" />.
    /// </summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>
    /// Session involved in the event, when known.
    /// </summary>
    public Guid? SessionId { get; init; }

    /// <summary>
    /// Authentication provider involved in the event, when known.
    /// </summary>
    public AuthenticationProviderKey? Provider { get; init; }

    /// <summary>
    /// Client IP address captured for audit. Treat as personal data.
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// Client user-agent captured for audit. Treat as user-supplied data.
    /// </summary>
    public string? UserAgent { get; init; }

    /// <summary>
    /// Request or trace correlation identifier safe for operational logs.
    /// </summary>
    public string? CorrelationId { get; init; }

    /// <summary>
    /// Provider-neutral outcome, such as success or failure.
    /// </summary>
    public string? Outcome { get; init; }

    /// <summary>
    /// Provider-neutral failure reason. Keep values generic enough for logs and administrative display.
    /// </summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Additional provider-neutral properties. Do not include secrets, raw tokens, hashes, credentials, or protected payloads.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
