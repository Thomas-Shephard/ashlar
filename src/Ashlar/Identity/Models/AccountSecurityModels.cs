using Ashlar.Auditing;

namespace Ashlar.Identity.Models;

/// <summary>
/// Request metadata for administrator account security operations.
/// </summary>
/// <param name="Audit">The audit context value.</param>
/// <param name="Tenant">The tenant context value.</param>
/// <param name="Reason">The reason value.</param>
public sealed record AccountSecurityOperationRequest(
    AuditContext Audit,
    TenantContext? Tenant = null,
    string? Reason = null);

/// <summary>
/// Result counts from an administrator account security operation.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="UserChanged">The user changed value.</param>
/// <param name="SessionsRevoked">The sessions revoked value.</param>
/// <param name="CredentialsRevoked">The credentials revoked value.</param>
public sealed record AccountSecurityOperationResult(
    Guid UserId,
    bool UserChanged = false,
    int SessionsRevoked = 0,
    int CredentialsRevoked = 0);

/// <summary>
/// Request metadata for a user security posture lookup.
/// </summary>
/// <param name="Tenant">The tenant context value.</param>
/// <param name="RecentSecurityEventWindow">The recent security event window value.</param>
public sealed record UserSecurityPostureRequest(
    TenantContext? Tenant = null,
    TimeSpan? RecentSecurityEventWindow = null);

/// <summary>
/// Non-secret account security posture details for a user.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="IsActive">The is active value.</param>
/// <param name="IsEmailVerified">The is email verified value.</param>
/// <param name="ConfiguredCredentials">The configured credentials value.</param>
/// <param name="IsMfaConfigured">The is MFA configured value.</param>
/// <param name="ActiveSessionCount">The active session count value.</param>
/// <param name="RecentSecurityEventCount">The recent security event count value.</param>
public sealed record UserSecurityPosture(
    Guid UserId,
    bool IsActive,
    bool IsEmailVerified,
    IReadOnlyList<AuthenticationProviderKey> ConfiguredCredentials,
    bool IsMfaConfigured,
    int ActiveSessionCount,
    int? RecentSecurityEventCount);

/// <summary>
/// Optional read model for stores that can efficiently count security events.
/// </summary>
public interface IUserSecurityEventSummaryRepository
{
    /// <summary>
    /// Counts recent security events for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="since">The since value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default);
}
