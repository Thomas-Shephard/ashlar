namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator user search.
/// </summary>
public sealed record SearchUsersRequest
{
    /// <summary>Optional query matched against normalized email addresses and display names.</summary>
    public string? Query { get; init; }

    /// <summary>Tenant scope to search. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <see cref="IncludeAllTenants" /> is enabled.</summary>
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
    /// <param name="request">Search request to validate before querying user administration data.</param>
    public static void ThrowIfInvalid(SearchUsersRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
    }
}

/// <summary>
/// Safe summary of a user for administrator display.
/// </summary>
/// <param name="UserId">Stable user identifier.</param>
/// <param name="DisplayEmail">Sanitized display/delivery email address returned for administrator display. This is not the normalized lookup form.</param>
/// <param name="Name">Optional user display name.</param>
/// <param name="TenantId">Tenant scope for the user, or <see langword="null" /> for a global user.</param>
/// <param name="AccountState">Current account state that controls sign-in eligibility.</param>
/// <param name="CanSignIn">Whether account state permits sign-in.</param>
/// <param name="IsEmailVerified">Whether <paramref name="DisplayEmail" /> is verified.</param>
/// <param name="CreatedAt">UTC time when the account was created.</param>
/// <param name="UpdatedAt">UTC time when account metadata or state last changed, when known.</param>
public sealed record UserSummary(
    Guid UserId,
    string DisplayEmail,
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
/// <param name="Items">Page of display-safe account summaries.</param>
/// <param name="Limit">Maximum page size requested.</param>
/// <param name="Offset">Number of matching records skipped before this page.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record UserSearchResult(
    IReadOnlyList<UserSummary> Items,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Display-safe administrator detail for a <paramref name="User" /> account.
/// </summary>
/// <param name="User">Display-safe user summary.</param>
/// <param name="SecurityPosture">The non-secret account-security posture for the <paramref name="User" /> account.</param>
public sealed record UserAdministrationDetail(
    UserSummary User,
    AccountSecurityPosture SecurityPosture);

/// <summary>
/// Request for administrator user detail.
/// </summary>
/// <param name="UserId">User to load.</param>
/// <param name="Tenant">Requested scope. Use <see cref="TenantContext.Global" /> for global users; leave <see langword="null" /> only when <paramref name="IncludeAllTenants" /> is enabled.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across all tenancy scopes. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="RecentSecurityEventWindow">Optional recent security event window for the embedded account-security posture.</param>
public sealed record UserAdministrationDetailRequest(
    Guid UserId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false,
    TimeSpan? RecentSecurityEventWindow = null)
{
    /// <summary>
    /// Throws when the user lookup request is not safe to execute.
    /// </summary>
    /// <param name="request">Lookup request to validate before loading administrator data.</param>
    public static void ThrowIfInvalid(UserAdministrationDetailRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
    }
}
