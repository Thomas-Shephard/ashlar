namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator authentication session search.
/// </summary>
public sealed record SearchAuthenticationSessionsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global users.</summary>
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
    /// <param name="request">The search request value.</param>
    public static void ThrowIfInvalid(SearchAuthenticationSessionsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
    }
}

/// <summary>
/// Safe summary of an authentication session for administrator display.
/// </summary>
/// <param name="Id">The <paramref name="Id" /> value.</param>
/// <param name="UserId">The <paramref name="UserId" /> value.</param>
/// <param name="TenantId">The tenant identifier value.</param>
/// <param name="CreatedAt">The creation time.</param>
/// <param name="AuthenticatedAt">The authentication time.</param>
/// <param name="PrimaryProvider">The primary authentication provider.</param>
/// <param name="AdditionalVerificationAt">The additional verification time.</param>
/// <param name="AdditionalVerificationProvider">The provider used for additional verification.</param>
/// <param name="AdditionalVerificationFactor">The factor family used for additional verification.</param>
/// <param name="ExpiresAt">The expiration time.</param>
/// <param name="LastSeenAt">The last observed time.</param>
/// <param name="RevokedAt">The revocation time.</param>
/// <param name="RevocationReason">The revocation reason value.</param>
/// <param name="IpAddress">The IP address value.</param>
/// <param name="UserAgent">The user agent value.</param>
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
    bool IsActive);

/// <summary>
/// Safe authentication session detail for administrator display.
/// </summary>
/// <param name="Id">The <paramref name="Id" /> value.</param>
/// <param name="UserId">The <paramref name="UserId" /> value.</param>
/// <param name="TenantId">The tenant identifier value.</param>
/// <param name="CreatedAt">The creation time.</param>
/// <param name="AuthenticatedAt">The authentication time.</param>
/// <param name="PrimaryProvider">The primary authentication provider.</param>
/// <param name="AdditionalVerificationAt">The additional verification time.</param>
/// <param name="AdditionalVerificationProvider">The provider used for additional verification.</param>
/// <param name="AdditionalVerificationFactor">The factor family used for additional verification.</param>
/// <param name="ExpiresAt">The expiration time.</param>
/// <param name="LastSeenAt">The last observed time.</param>
/// <param name="RevokedAt">The revocation time.</param>
/// <param name="RevocationReason">The revocation reason value.</param>
/// <param name="IpAddress">The IP address value.</param>
/// <param name="UserAgent">The user agent value.</param>
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
/// <param name="Items">The session items value.</param>
/// <param name="Limit">The limit value.</param>
/// <param name="Offset">The offset value.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record AuthenticationSessionSearchResult(
    IReadOnlyList<AuthenticationSessionAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for administrator authentication session detail.
/// </summary>
/// <param name="SessionId">The session id value.</param>
/// <param name="Tenant">The requested scope. Use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record AuthenticationSessionAdministrationDetailRequest(
    Guid SessionId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false)
{
    /// <summary>
    /// Throws when the authentication session detail request is not safe to execute.
    /// </summary>
    /// <param name="request">The detail request value.</param>
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
