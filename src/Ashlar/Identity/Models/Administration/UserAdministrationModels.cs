namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator user search.
/// </summary>
public sealed record SearchUsersRequest
{
    /// <summary>Optional case-insensitive email or name query.</summary>
    public string? Query { get; init; }

    /// <summary>Optional tenant scope. <see langword="null" /> means unscoped/admin-wide search.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Optional active state filter.</summary>
    public bool? IsActive { get; init; }

    /// <summary>Optional email verification filter.</summary>
    public bool? IsEmailVerified { get; init; }

    /// <summary>Maximum number of users to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of users to skip.</summary>
    public int Offset { get; init; }
}

/// <summary>
/// Safe summary of a user for administrator display.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="Email">The <paramref name="Email" /> value.</param>
/// <param name="Name">The name value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="IsActive">Whether the user is active.</param>
/// <param name="IsEmailVerified">Whether <paramref name="Email" /> is verified.</param>
/// <param name="CreatedAt">The creation time.</param>
/// <param name="UpdatedAt">The update time.</param>
public sealed record UserSummary(
    Guid UserId,
    string Email,
    string? Name,
    Guid? TenantId,
    bool IsActive,
    bool IsEmailVerified,
    DateTimeOffset CreatedAt,
    DateTimeOffset? UpdatedAt);

/// <summary>
/// Paged user search result.
/// </summary>
/// <param name="Users">The users value.</param>
/// <param name="Limit">The limit value.</param>
/// <param name="Offset">The offset value.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record UserSearchResult(
    IReadOnlyList<UserSummary> Users,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Safe administrator <paramref name="User" /> detail.
/// </summary>
/// <param name="User">The user summary value.</param>
/// <param name="SecurityPosture">The security posture value.</param>
public sealed record UserAdministrationDetail(
    UserSummary User,
    UserSecurityPosture SecurityPosture);
