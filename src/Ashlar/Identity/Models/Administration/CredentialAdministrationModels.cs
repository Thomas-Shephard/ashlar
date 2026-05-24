namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator credential search.
/// </summary>
public sealed record SearchCredentialsRequest
{
    /// <summary>Optional tenant scope. <see langword="null" /> means unscoped/admin-wide search.</summary>
    public TenantContext? Tenant { get; init; }

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
}

/// <summary>
/// Safe summary of a credential for administrator display.
/// </summary>
/// <param name="CredentialId">The credential id value.</param>
/// <param name="UserId">The user id value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="Provider">The authentication provider value.</param>
/// <param name="Purpose">The credential purpose value.</param>
/// <param name="Status">The lifecycle status value.</param>
/// <param name="IsAvailable">Whether this credential is currently active, unrevoked, and unexpired.</param>
/// <param name="CreatedAt">The creation time.</param>
/// <param name="UpdatedAt">The update time.</param>
/// <param name="LastUsedAt">The last successful use time.</param>
/// <param name="ExpiresAt">The expiration time.</param>
/// <param name="RevokedAt">The revocation time.</param>
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
/// Safe credential detail for administrator display.
/// </summary>
/// <param name="CredentialId">The credential id value.</param>
/// <param name="UserId">The user id value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="Provider">The authentication provider value.</param>
/// <param name="Purpose">The credential purpose value.</param>
/// <param name="Status">The lifecycle status value.</param>
/// <param name="IsAvailable">Whether this credential is currently active, unrevoked, and unexpired.</param>
/// <param name="CreatedAt">The creation time.</param>
/// <param name="UpdatedAt">The update time.</param>
/// <param name="LastUsedAt">The last successful use time.</param>
/// <param name="ExpiresAt">The expiration time.</param>
/// <param name="RevokedAt">The revocation time.</param>
public sealed record CredentialAdministrationDetail(
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
/// <param name="Items">The credential items value.</param>
/// <param name="Limit">The limit value.</param>
/// <param name="Offset">The offset value.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record CredentialSearchResult(
    IReadOnlyList<CredentialAdministrationSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);
