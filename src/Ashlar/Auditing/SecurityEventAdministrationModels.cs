namespace Ashlar.Auditing;

/// <summary>
/// Request for administrator security event search.
/// </summary>
public sealed record SearchSecurityEventsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global events; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
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
    /// <param name="request">Request to validate before repository access.</param>
    public static void ThrowIfInvalid(SearchSecurityEventsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
    }
}

/// <summary>
/// Safe summary of a security event for administrator display.
/// </summary>
/// <param name="EventId">Stable identifier of the recorded event.</param>
/// <param name="EventType">Normalized security event type.</param>
/// <param name="OccurredAt">UTC time when the event occurred.</param>
/// <param name="UserId">Affected user identifier, when the event is user-scoped.</param>
/// <param name="TenantId">Tenant scope associated with the event, when available.</param>
/// <param name="ActorUserId">Administrator or actor user identifier, when available.</param>
/// <param name="SessionId">Related application session identifier, when available.</param>
/// <param name="Provider">Authentication source associated with the event, when available.</param>
/// <param name="IpAddress">Client IP address captured for the event. Treat as personal data.</param>
/// <param name="UserAgent">Client user-agent text captured for the event. It may be user supplied.</param>
/// <param name="CorrelationId">Host-defined correlation identifier, when available.</param>
/// <param name="Outcome">Normalized outcome for the event.</param>
/// <param name="FailureReason">Normalized failure reason, when the event failed.</param>
/// <param name="Properties">Diagnostic properties safe for administrator display.</param>
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
/// <param name="Events">Security summaries in the current page.</param>
/// <param name="Limit">Maximum number of summaries requested for the page.</param>
/// <param name="Offset">Number of records skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record SecurityEventSearchResult(
    IReadOnlyList<SecurityEventSummary> Events,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for administrator security event detail.
/// </summary>
/// <param name="EventId">Identifier of the event to retrieve.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global events; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record SecurityEventAdministrationDetailRequest(
    Guid EventId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false)
{
    /// <summary>
    /// Throws when the security event detail request is not safe to execute.
    /// </summary>
    /// <param name="request">Request to validate before repository access.</param>
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
