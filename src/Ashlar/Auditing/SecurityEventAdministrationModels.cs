namespace Ashlar.Auditing;

/// <summary>
/// Request for administrator security event search.
/// </summary>
public sealed record SearchSecurityEventsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global events.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

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

    /// <summary>
    /// Throws when the security event administration search request is not safe to execute.
    /// </summary>
    /// <param name="request">The search request value.</param>
    public static void ThrowIfInvalid(SearchSecurityEventsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
    }
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

/// <summary>
/// Request for administrator security event detail.
/// </summary>
/// <param name="EventId">The event id value.</param>
/// <param name="Tenant">The requested scope. Use <see cref="TenantContext.Global" /> for global events.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record SecurityEventAdministrationDetailRequest(
    Guid EventId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false)
{
    /// <summary>
    /// Throws when the security event detail request is not safe to execute.
    /// </summary>
    /// <param name="request">The detail request value.</param>
    public static void ThrowIfInvalid(SecurityEventAdministrationDetailRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.EventId == Guid.Empty)
        {
            throw new ArgumentException("Event ID cannot be empty.", nameof(request));
        }
    }
}
