namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores durable remembered MFA devices.
/// </summary>
public interface IRememberedMfaDeviceRepository
{
    /// <summary>Persists a remembered MFA device.</summary>
    /// <param name="device">The device to persist.</param>
    /// <param name="cancellationToken">A token that can cancel persistence.</param>
    /// <returns>A task that completes when the device has been stored.</returns>
    Task CreateAsync(RememberedMfaDevice device, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a device by its public token selector.</summary>
    /// <param name="tokenSelector">The public token selector.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matched device, if any.</returns>
    Task<RememberedMfaDevice?> GetByTokenSelectorAsync(string tokenSelector, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a device by identifier.</summary>
    /// <param name="deviceId">Public identifier returned by remembered-device management APIs.</param>
    /// <param name="cancellationToken">A token that can cancel lookup.</param>
    /// <returns>The matched device, if any.</returns>
    Task<RememberedMfaDevice?> GetAsync(Guid deviceId, CancellationToken cancellationToken = default);

    /// <summary>Updates the last successful use timestamp.</summary>
    /// <param name="deviceId">Public identifier returned by remembered-device management APIs.</param>
    /// <param name="lastUsedAt">UTC time when the token last satisfied additional verification.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns><see langword="true" /> when the row was updated.</returns>
    Task<bool> UpdateLastUsedAsync(Guid deviceId, DateTimeOffset lastUsedAt, CancellationToken cancellationToken = default);

    /// <summary>Lists devices for a user and optional tenant scope.</summary>
    /// <param name="userId">User that owns the remembered devices.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted; <see cref="TenantContext.Global" /> means global devices only.</param>
    /// <param name="activeOnly">Whether only active devices should be returned.</param>
    /// <param name="now">The timestamp used for active filtering.</param>
    /// <param name="cancellationToken">A token that can cancel the query.</param>
    /// <returns>The matched devices.</returns>
    Task<IReadOnlyList<RememberedMfaDevice>> ListForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Counts devices for a user and optional tenant scope.</summary>
    /// <param name="userId">User that owns the remembered devices.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted; <see cref="TenantContext.Global" /> means global devices only.</param>
    /// <param name="activeOnly">Whether only active devices should be counted.</param>
    /// <param name="now">The timestamp used for active filtering.</param>
    /// <param name="cancellationToken">A token that can cancel the count query.</param>
    /// <returns>The matched device count.</returns>
    Task<int> CountForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Revokes one device owned by a user.</summary>
    /// <param name="deviceId">Public identifier returned by remembered-device management APIs.</param>
    /// <param name="userId">User that must own the remembered device.</param>
    /// <param name="revokedAt">UTC time to record as the device revocation timestamp.</param>
    /// <param name="reason">Optional provider-neutral, display-safe revocation reason.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted; <see cref="TenantContext.Global" /> means global devices only.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns><see langword="true" /> when a device was revoked.</returns>
    Task<bool> RevokeAsync(Guid deviceId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);

    /// <summary>Revokes all devices owned by a user.</summary>
    /// <param name="userId">User that owns the remembered devices.</param>
    /// <param name="revokedAt">UTC time to record as each device revocation timestamp.</param>
    /// <param name="reason">Optional provider-neutral, display-safe revocation reason.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted; <see cref="TenantContext.Global" /> means global devices only.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>The number of revoked devices.</returns>
    Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);
}
