namespace Ashlar.Auditing;

/// <summary>
/// Request for administrator security event search.
/// </summary>
public sealed record SearchSecurityEventsRequest
{
    /// <summary>Optional tenant scope. <see langword="null" /> means unscoped/admin-wide search.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Optional user filter.</summary>
    public Guid? UserId { get; init; }

    /// <summary>Optional actor user filter.</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>Optional session filter.</summary>
    public Guid? SessionId { get; init; }

    /// <summary>Optional event type filter.</summary>
    public IReadOnlySet<string>? EventTypes { get; init; }

    /// <summary>Optional event outcome filter.</summary>
    public string? Outcome { get; init; }

    /// <summary>Optional failure reason filter.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Optional authentication provider filter.</summary>
    public AuthenticationProviderKey? Provider { get; init; }

    /// <summary>Inclusive lower occurrence bound.</summary>
    public DateTimeOffset? OccurredFrom { get; init; }

    /// <summary>Inclusive upper occurrence bound.</summary>
    public DateTimeOffset? OccurredTo { get; init; }

    /// <summary>Maximum number of events to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of events to skip.</summary>
    public int Offset { get; init; }
}

/// <summary>
/// Safe summary of a security event for administrator display.
/// </summary>
/// <param name="EventId">The event id value.</param>
/// <param name="EventType">The event type value.</param>
/// <param name="OccurredAt">The occurrence time.</param>
/// <param name="UserId">The user id value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="ActorUserId">The actor user id value.</param>
/// <param name="SessionId">The session id value.</param>
/// <param name="Provider">The authentication provider value.</param>
/// <param name="IpAddress">The IP address value.</param>
/// <param name="UserAgent">The user agent value.</param>
/// <param name="CorrelationId">The correlation id value.</param>
/// <param name="Outcome">The outcome value.</param>
/// <param name="FailureReason">The failure reason value.</param>
/// <param name="Properties">The safe diagnostic properties.</param>
public sealed record SecurityEventSummary(
    Guid EventId,
    string EventType,
    DateTimeOffset OccurredAt,
    Guid? UserId,
    Guid? TenantId,
    Guid? ActorUserId,
    Guid? SessionId,
    AuthenticationProviderKey? Provider,
    string? IpAddress,
    string? UserAgent,
    string? CorrelationId,
    string? Outcome,
    string? FailureReason,
    IReadOnlyDictionary<string, string>? Properties);

/// <summary>
/// Paged security event search result.
/// </summary>
/// <param name="Events">The events value.</param>
/// <param name="Limit">The limit value.</param>
/// <param name="Offset">The offset value.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record SecurityEventSearchResult(
    IReadOnlyList<SecurityEventSummary> Events,
    int Limit,
    int Offset,
    bool HasMore);
