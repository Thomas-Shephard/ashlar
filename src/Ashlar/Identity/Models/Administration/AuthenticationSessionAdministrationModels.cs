namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator authentication session search.
/// </summary>
public sealed record SearchAuthenticationSessionsRequest
{
    /// <summary>Optional tenant scope. <see langword="null" /> means unscoped/admin-wide search.</summary>
    public TenantContext? Tenant { get; init; }

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
