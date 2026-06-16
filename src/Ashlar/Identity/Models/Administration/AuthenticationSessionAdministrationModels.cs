namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator authentication session search.
/// </summary>
public sealed record SearchAuthenticationSessionsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Optional user filter.</summary>
    public Guid? UserId { get; init; }

    /// <summary>Optional primary authentication provider filter.</summary>
    public AuthenticationProviderKey? PrimaryProvider { get; init; }

    /// <summary>Optional active state filter.</summary>
    public bool? Active { get; init; }

    /// <summary>Optional revoked state filter.</summary>
    public bool? Revoked { get; init; }

    /// <summary>Inclusive lower creation time bound.</summary>
    public DateTimeOffset? CreatedFrom { get; init; }

    /// <summary>Inclusive upper creation time bound.</summary>
    public DateTimeOffset? CreatedTo { get; init; }

    /// <summary>Inclusive lower expiration time bound.</summary>
    public DateTimeOffset? ExpiresFrom { get; init; }

    /// <summary>Inclusive upper expiration time bound.</summary>
    public DateTimeOffset? ExpiresTo { get; init; }

    /// <summary>Inclusive lower last-seen time bound.</summary>
    public DateTimeOffset? LastSeenFrom { get; init; }

    /// <summary>Inclusive upper last-seen time bound.</summary>
    public DateTimeOffset? LastSeenTo { get; init; }

    /// <summary>Maximum number of sessions to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of sessions to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the authentication session administration search request is not safe to execute.
    /// </summary>
    /// <param name="request">Search request to validate before querying session administration data.</param>
    public static void ThrowIfInvalid(SearchAuthenticationSessionsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
    }
}

/// <summary>
/// Safe summary of an authentication session for administrator display.
/// </summary>
/// <param name="Id">Stable session identifier.</param>
/// <param name="UserId">User that owns the session.</param>
/// <param name="TenantId">Tenant scope for the session owner, or <see langword="null" /> for a global user.</param>
/// <param name="CreatedAt">UTC time when the session was issued.</param>
/// <param name="AuthenticatedAt">UTC time when primary authentication completed for the session.</param>
/// <param name="PrimaryProvider">Provider that authenticated the primary credential, when captured.</param>
/// <param name="AdditionalVerificationAt">UTC time when MFA or step-up verification completed for the session, when captured.</param>
/// <param name="AdditionalVerificationProvider">Provider that completed additional verification, when captured.</param>
/// <param name="AdditionalVerificationFactor">Provider-neutral factor family that satisfied MFA or step-up verification.</param>
/// <param name="ExpiresAt">UTC time after which the session is no longer valid.</param>
/// <param name="LastSeenAt">UTC time when validation last observed the session, when captured.</param>
/// <param name="RevokedAt">UTC time when the session was revoked, when applicable.</param>
/// <param name="RevocationReason">Provider-neutral, display-safe reason recorded when the session was revoked.</param>
/// <param name="IpAddress">Client IP address associated with the session, when captured.</param>
/// <param name="UserAgent">Client user-agent text associated with the session, when captured.</param>
/// <param name="IsActive">Whether the session is currently active.</param>
public sealed record AuthenticationSessionAdministrationSummary(
    Guid Id,
    Guid UserId,
    Guid? TenantId,
    DateTimeOffset CreatedAt,
    DateTimeOffset? AuthenticatedAt,
    AuthenticationProviderKey? PrimaryProvider,
    DateTimeOffset? AdditionalVerificationAt,
    AuthenticationProviderKey? AdditionalVerificationProvider,
    string? AdditionalVerificationFactor,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastSeenAt,
    DateTimeOffset? RevokedAt,
    string? RevocationReason,
    string? IpAddress,
    string? UserAgent,
    bool IsActive)
{
    /// <summary>
    /// Creates the administrator detail view for this session summary.
    /// </summary>
    /// <returns>A detail model with the same display-safe session fields.</returns>
    public AuthenticationSessionAdministrationDetail ToDetail()
    {
        return new AuthenticationSessionAdministrationDetail(
            Id,
            UserId,
            TenantId,
            CreatedAt,
            AuthenticatedAt,
            PrimaryProvider,
            AdditionalVerificationAt,
            AdditionalVerificationProvider,
            AdditionalVerificationFactor,
            ExpiresAt,
            LastSeenAt,
            RevokedAt,
            RevocationReason,
            IpAddress,
            UserAgent,
            IsActive);
    }
}

/// <summary>
/// Safe authentication session detail for administrator display.
/// </summary>
/// <param name="Id">Stable session identifier.</param>
/// <param name="UserId">User that owns the session.</param>
/// <param name="TenantId">Tenant scope for the session owner, or <see langword="null" /> for a global user.</param>
/// <param name="CreatedAt">UTC time when the session was issued.</param>
/// <param name="AuthenticatedAt">UTC time when primary authentication completed for the session.</param>
/// <param name="PrimaryProvider">Provider that authenticated the primary credential, when captured.</param>
/// <param name="AdditionalVerificationAt">UTC time when MFA or step-up verification completed for the session, when captured.</param>
/// <param name="AdditionalVerificationProvider">Provider that completed additional verification, when captured.</param>
/// <param name="AdditionalVerificationFactor">Provider-neutral factor family that satisfied MFA or step-up verification.</param>
/// <param name="ExpiresAt">UTC time after which the session is no longer valid.</param>
/// <param name="LastSeenAt">UTC time when validation last observed the session, when captured.</param>
/// <param name="RevokedAt">UTC time when the session was revoked, when applicable.</param>
/// <param name="RevocationReason">Provider-neutral, display-safe reason recorded when the session was revoked.</param>
/// <param name="IpAddress">Client IP address associated with the session, when captured.</param>
/// <param name="UserAgent">Client user-agent text associated with the session, when captured.</param>
/// <param name="IsActive">Whether the session is currently active.</param>
public sealed record AuthenticationSessionAdministrationDetail(
    Guid Id,
    Guid UserId,
    Guid? TenantId,
    DateTimeOffset CreatedAt,
    DateTimeOffset? AuthenticatedAt,
    AuthenticationProviderKey? PrimaryProvider,
    DateTimeOffset? AdditionalVerificationAt,
    AuthenticationProviderKey? AdditionalVerificationProvider,
    string? AdditionalVerificationFactor,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastSeenAt,
    DateTimeOffset? RevokedAt,
    string? RevocationReason,
    string? IpAddress,
    string? UserAgent,
    bool IsActive);

/// <summary>
/// Paged authentication session search result.
/// </summary>
/// <param name="Items">Page of display-safe session summaries.</param>
/// <param name="Limit">Maximum page size requested.</param>
/// <param name="Offset">Number of matching sessions skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record AuthenticationSessionSearchResult(
    IReadOnlyList<AuthenticationSessionAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for administrator authentication session detail.
/// </summary>
/// <param name="SessionId">Session to load.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record AuthenticationSessionAdministrationDetailRequest(
    Guid SessionId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false)
{
    /// <summary>
    /// Throws when the authentication session detail request is not safe to execute.
    /// </summary>
    /// <param name="request">Detail request to validate before loading administrator data.</param>
    public static void ThrowIfInvalid(AuthenticationSessionAdministrationDetailRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.SessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(request));
        }
    }
}
