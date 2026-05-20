using Ashlar.Auditing;

namespace Ashlar.Authorization.Models;

/// <summary>
/// Represents the create authorization grant request data model.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="TenantId">The tenant id value.</param>
/// <param name="ScopeType">The scope type value.</param>
/// <param name="ScopeId">The scope id value.</param>
/// <param name="Role">The role value.</param>
/// <param name="Permission">The permission value.</param>
/// <param name="ExpiresAt">The expires at value.</param>
/// <param name="Metadata">The metadata value.</param>
/// <param name="Audit">The audit context value.</param>
public sealed record CreateAuthorizationGrantRequest(
    Guid UserId,
    Guid? TenantId = null,
    string? ScopeType = null,
    string? ScopeId = null,
    string? Role = null,
    string? Permission = null,
    DateTimeOffset? ExpiresAt = null,
    string? Metadata = null,
    AuditContext? Audit = null);
