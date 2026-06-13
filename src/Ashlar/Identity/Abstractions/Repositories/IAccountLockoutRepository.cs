namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores automatic account lockout state for resolved users.
/// </summary>
public interface IAccountLockoutRepository
{
    /// <summary>
    /// Searches stored automatic lockout state for administrative operations.
    /// </summary>
    /// <param name="request">Tenant scope, filters, and paging limits for the lockout search.</param>
    /// <param name="now">The timestamp used for active lockout filtering.</param>
    /// <param name="cancellationToken">A token that can cancel lockout search.</param>
    /// <returns>The matching lockout records.</returns>
    Task<IReadOnlyList<AccountLockoutRecord>> SearchAsync(SearchAccountLockoutsRequest request, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves lockout state for a user, tenant, and provider.
    /// </summary>
    /// <param name="userId">User whose automatic lockout state should be retrieved.</param>
    /// <param name="tenantId">Tenant scope for the user, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="cancellationToken">A token that can cancel lockout lookup.</param>
    /// <returns>The matching lockout record, or <see langword="null" /> when no failures are stored.</returns>
    Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically records a failed credential verification.
    /// </summary>
    /// <param name="userId">User whose failed primary credential attempt should be recorded.</param>
    /// <param name="tenantId">Tenant scope for the user, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="failedAt">UTC time to record for the failed credential attempt.</param>
    /// <param name="failureThreshold">The configured threshold for automatic lockout.</param>
    /// <param name="lockoutDuration">The duration of newly activated automatic lockouts.</param>
    /// <param name="cancellationToken">A token that can cancel failure recording.</param>
    /// <returns>The updated lockout record and whether this write activated a new automatic lockout.</returns>
    Task<AccountLockoutRecordUpdate> RecordFailureAsync(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        DateTimeOffset failedAt,
        int failureThreshold,
        TimeSpan lockoutDuration,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears stored automatic lockout failures for a user, tenant, and provider.
    /// </summary>
    /// <param name="userId">User whose automatic lockout state should be cleared.</param>
    /// <param name="tenantId">Tenant scope for the user, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="cancellationToken">A token that can cancel lockout reset.</param>
    /// <returns><see langword="true" /> when stored state was cleared.</returns>
    Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default);
}
