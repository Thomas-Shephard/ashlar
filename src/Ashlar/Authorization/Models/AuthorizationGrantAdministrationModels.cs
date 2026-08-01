namespace Ashlar.Authorization.Models;

/// <summary>
/// Administrator-facing lifecycle state for an authorization grant.
/// </summary>
public enum AuthorizationGrantAdministrationStatus
{
    /// <summary>The grant is not revoked and has not expired.</summary>
    Active,

    /// <summary>The grant has a revocation timestamp.</summary>
    Revoked,

    /// <summary>The grant is not revoked, but its expiry time has passed.</summary>
    Expired
}

/// <summary>
/// Request for administrator authorization grant search.
/// </summary>
public sealed record SearchAuthorizationGrantsRequest
{
    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global grants; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Optional user filter.</summary>
    public Guid? UserId { get; init; }

    /// <summary>Optional role filter.</summary>
    public string? Role { get; init; }

    /// <summary>Optional permission filter.</summary>
    public string? Permission { get; init; }

    /// <summary>Optional resource type filter.</summary>
    public string? ScopeType { get; init; }

    /// <summary>Optional resource identifier filter. Must be paired with <see cref="ScopeType" />.</summary>
    public string? ScopeId { get; init; }

    /// <summary>Optional lifecycle status filter.</summary>
    public AuthorizationGrantAdministrationStatus? Status { get; init; }

    /// <summary>Inclusive lower creation time bound.</summary>
    public DateTimeOffset? CreatedFrom { get; init; }

    /// <summary>Inclusive upper creation time bound.</summary>
    public DateTimeOffset? CreatedTo { get; init; }

    /// <summary>Inclusive lower expiry time bound.</summary>
    public DateTimeOffset? ExpiresFrom { get; init; }

    /// <summary>Inclusive upper expiry time bound.</summary>
    public DateTimeOffset? ExpiresTo { get; init; }

    /// <summary>Inclusive lower revocation time bound.</summary>
    public DateTimeOffset? RevokedFrom { get; init; }

    /// <summary>Inclusive upper revocation time bound.</summary>
    public DateTimeOffset? RevokedTo { get; init; }

    /// <summary>Maximum number of grants to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of matching grants to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the authorization grant administration search request is not safe to execute.
    /// </summary>
    /// <param name="request">Search request to validate before querying grant administration data.</param>
    public static void ThrowIfInvalid(SearchAuthorizationGrantsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        AuthorizationGrantService.ValidateScopeShape(request.ScopeType, request.ScopeId);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
    }
}

/// <summary>
/// Safe summary of an authorization grant for administrator display.
/// </summary>
/// <param name="Id">Stable grant identifier.</param>
/// <param name="UserId">User that receives the <paramref name="Role" /> or <paramref name="Permission" /> value.</param>
/// <param name="TenantId">Tenant scope for the grant, or <see langword="null" /> for a global grant.</param>
/// <param name="ScopeType">Resource type that constrains the grant, when present.</param>
/// <param name="ScopeId">Resource identifier that constrains the grant, when present.</param>
/// <param name="Role">Assigned role value, when present.</param>
/// <param name="Permission">Assigned permission value, when present.</param>
/// <param name="CreatedAt">UTC time when the grant was created.</param>
/// <param name="ExpiresAt">UTC time after which the grant no longer applies, when configured.</param>
/// <param name="RevokedAt">UTC time when the grant was revoked, when applicable.</param>
/// <param name="Status">Lifecycle state derived from revocation and expiry timestamps.</param>
public sealed record AuthorizationGrantAdministrationSummary(
    Guid Id,
    Guid UserId,
    Guid? TenantId,
    string? ScopeType,
    string? ScopeId,
    string? Role,
    string? Permission,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt,
    AuthorizationGrantAdministrationStatus Status);

/// <summary>
/// Paged authorization grant search result.
/// </summary>
/// <param name="Items">Page of display-safe grant summaries.</param>
/// <param name="Limit">Maximum page size requested.</param>
/// <param name="Offset">Number of matching grants skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record AuthorizationGrantSearchResult(
    IReadOnlyList<AuthorizationGrantAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for an administrator authorization grant single-item lookup.
/// </summary>
/// <param name="GrantId">Grant to load.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global grants; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across all tenancy scopes. Cannot be combined with <paramref name="Tenant" />.</param>
public sealed record AuthorizationGrantAdministrationLookupRequest(
    Guid GrantId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false)
{
    /// <summary>
    /// Throws when the authorization grant lookup request is not safe to execute.
    /// </summary>
    /// <param name="request">Lookup request to validate before loading administrator data.</param>
    public static void ThrowIfInvalid(AuthorizationGrantAdministrationLookupRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.GrantId == Guid.Empty)
        {
            throw new ArgumentException("Grant ID cannot be empty.", nameof(request));
        }
    }
}
