namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores automatic account lockout state for resolved users.
/// </summary>
public interface IAccountLockoutRepository
{
    /// <summary>
    /// Retrieves lockout state for a user, tenant, and provider.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The matching lockout record, or <see langword="null" /> when no failures are stored.</returns>
    Task<AccountLockoutRecord?> GetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically records a failed credential verification.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="failedAt">The failure timestamp.</param>
    /// <param name="failureThreshold">The configured threshold for automatic lockout.</param>
    /// <param name="lockoutDuration">The duration of newly activated automatic lockouts.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
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
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, or <see langword="null" /> for a global user.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns><see langword="true" /> when stored state was cleared.</returns>
    Task<bool> ResetAsync(Guid userId, Guid? tenantId, AuthenticationProviderKey provider, CancellationToken cancellationToken = default);
}
