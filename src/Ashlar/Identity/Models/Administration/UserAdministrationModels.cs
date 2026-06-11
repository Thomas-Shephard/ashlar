namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator user search.
/// </summary>
public sealed record SearchUsersRequest
{
    /// <summary>Optional case-insensitive email or name query.</summary>
    public string? Query { get; init; }

    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global users.</summary>
    public TenantContext? Tenant { get; init; }

    /// <summary>Whether to search across all tenant scopes. Cannot be combined with <see cref="Tenant" />.</summary>
    public bool IncludeAllTenants { get; init; }

    /// <summary>Optional account state filter.</summary>
    public UserAccountState? AccountState { get; init; }

    /// <summary>Optional email verification filter.</summary>
    public bool? IsEmailVerified { get; init; }

    /// <summary>Maximum number of users to return.</summary>
    public int Limit { get; init; } = 50;

    /// <summary>Number of users to skip.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Throws when the user administration search request is not safe to execute.
    /// </summary>
    /// <param name="request">The search request value.</param>
    public static void ThrowIfInvalid(SearchUsersRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants, request);
    }
}

/// <summary>
/// Safe summary of a user for administrator display.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="Email">The <paramref name="Email" /> value.</param>
/// <param name="Name">The name value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="AccountState">The account state value.</param>
/// <param name="CanSignIn">Whether account state permits sign-in.</param>
/// <param name="IsEmailVerified">Whether <paramref name="Email" /> is verified.</param>
/// <param name="CreatedAt">The creation time.</param>
/// <param name="UpdatedAt">The update time.</param>
public sealed record UserSummary(
    Guid UserId,
    string Email,
    string? Name,
    Guid? TenantId,
    UserAccountState AccountState,
    bool CanSignIn,
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

/// <summary>
/// Request for administrator user detail.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="Tenant">The requested scope. Use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="RecentSecurityEventWindow">Optional recent security event window for the embedded security posture.</param>
public sealed record UserAdministrationDetailRequest(
    Guid UserId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false,
    TimeSpan? RecentSecurityEventWindow = null)
{
    /// <summary>
    /// Throws when the user detail request is not safe to execute.
    /// </summary>
    /// <param name="request">The detail request value.</param>
    public static void ThrowIfInvalid(UserAdministrationDetailRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants, request);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
    }
}
