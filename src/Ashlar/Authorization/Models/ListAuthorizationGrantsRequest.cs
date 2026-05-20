namespace Ashlar.Authorization.Models;

/// <summary>
/// Represents the list authorization grants request data model.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="ScopeType">The scope type value.</param>
/// <param name="ScopeId">The scope id value.</param>
/// <param name="ActiveOnly">The active only value.</param>
/// <param name="ExactMatch">The exact match value.</param>
public sealed record ListAuthorizationGrantsRequest(
    Guid UserId,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null,
    bool ActiveOnly = false,
    bool ExactMatch = false);


