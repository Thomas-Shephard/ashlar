namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator credential search.
/// </summary>
public sealed record SearchCredentialsRequest
{
    /// <summary>Authenticated actor, active session, fresh proof, and audit metadata.</summary>
    public AccountSecurityActorContext? Actor { get; init; }

    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Optional user filter.</summary>
    public Guid? UserId { get; init; }

    /// <summary>Optional authentication provider filter.</summary>
    public AuthenticationProviderKey? Provider { get; init; }

    /// <summary>Optional provider-neutral credential purpose filter.</summary>
    public string? Purpose { get; init; }

    /// <summary>Optional lifecycle status filter.</summary>
    public CredentialStatus? Status { get; init; }

    /// <summary>Optional availability filter evaluated with the service clock.</summary>
    public bool? Available { get; init; }

    /// <summary>Optional revoked state filter.</summary>
    public bool? Revoked { get; init; }

    /// <summary>Inclusive lower creation time bound.</summary>
    public DateTimeOffset? CreatedFrom { get; init; }

    /// <summary>Inclusive upper creation time bound.</summary>
    public DateTimeOffset? CreatedTo { get; init; }

    /// <summary>Inclusive lower update time bound.</summary>
    public DateTimeOffset? UpdatedFrom { get; init; }

    /// <summary>Inclusive upper update time bound.</summary>
    public DateTimeOffset? UpdatedTo { get; init; }

    /// <summary>Inclusive lower last-used time bound.</summary>
    public DateTimeOffset? LastUsedFrom { get; init; }

    /// <summary>Inclusive upper last-used time bound.</summary>
    public DateTimeOffset? LastUsedTo { get; init; }

    /// <summary>Inclusive lower expiration time bound.</summary>
    public DateTimeOffset? ExpiresFrom { get; init; }

    /// <summary>Inclusive upper expiration time bound.</summary>
    public DateTimeOffset? ExpiresTo { get; init; }

    /// <summary>Maximum number of credentials to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of credentials to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the credential administration search request is not safe to execute.
    /// </summary>
    /// <param name="request">Search request to validate before querying credential administration data.</param>
    public static void ThrowIfInvalid(SearchCredentialsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
    }
}

/// <summary>
/// Safe summary of a credential for administrator display.
/// </summary>
/// <param name="CredentialId">Stable credential identifier.</param>
/// <param name="UserId">User that owns the credential.</param>
/// <param name="TenantId">Tenant scope for the credential owner, or <see langword="null" /> for a global user.</param>
/// <param name="Provider">Authentication mechanism that owns the credential.</param>
/// <param name="Purpose">Credential purpose, when one is assigned.</param>
/// <param name="Status">Current credential lifecycle status.</param>
/// <param name="IsAvailable">Whether this credential is currently active, unrevoked, and unexpired.</param>
/// <param name="CreatedAt">UTC time when the credential was created.</param>
/// <param name="UpdatedAt">UTC time when credential metadata or lifecycle state last changed, when known.</param>
/// <param name="LastUsedAt">UTC time when the credential last authenticated successfully, when known.</param>
/// <param name="ExpiresAt">UTC time after which the credential is unavailable, when one is set.</param>
/// <param name="RevokedAt">UTC time when the credential was revoked, when applicable.</param>
public sealed record CredentialAdministrationSummary(
    Guid CredentialId,
    Guid UserId,
    Guid? TenantId,
    AuthenticationProviderKey Provider,
    string? Purpose,
    CredentialStatus Status,
    bool IsAvailable,
    DateTimeOffset CreatedAt,
    DateTimeOffset? UpdatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt);

/// <summary>
/// Paged credential search result.
/// </summary>
/// <param name="Items">Page of display-safe credential summaries.</param>
/// <param name="Limit">Maximum page size requested.</param>
/// <param name="Offset">Number of matching credentials skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record CredentialSearchResult(
    IReadOnlyList<CredentialAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Request for an administrator credential single-item lookup.
/// </summary>
/// <param name="CredentialId">Credential to load.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across all tenancy scopes. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="Actor">Authenticated actor, active session, fresh proof, and audit metadata.</param>
public sealed record CredentialAdministrationLookupRequest(
    Guid CredentialId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false,
    AccountSecurityActorContext? Actor = null)
{
    /// <summary>
    /// Throws when the credential lookup request is not safe to execute.
    /// </summary>
    /// <param name="request">Lookup request to validate before loading administrator data.</param>
    public static void ThrowIfInvalid(CredentialAdministrationLookupRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.CredentialId == Guid.Empty)
        {
            throw new ArgumentException("Credential ID cannot be empty.", nameof(request));
        }
    }
}
