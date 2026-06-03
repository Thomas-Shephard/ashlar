namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Stores durable remembered MFA devices.
/// </summary>
public interface IRememberedMfaDeviceRepository
{
    /// <summary>Persists a remembered MFA device.</summary>
    /// <param name="device">The device to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result.</returns>
    Task CreateAsync(RememberedMfaDevice device, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a device by its public token selector.</summary>
    /// <param name="tokenSelector">The public token selector.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The matched device, if any.</returns>
    Task<RememberedMfaDevice?> GetByTokenSelectorAsync(string tokenSelector, CancellationToken cancellationToken = default);

    /// <summary>Retrieves a device by identifier.</summary>
    /// <param name="deviceId">The public device identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The matched device, if any.</returns>
    Task<RememberedMfaDevice?> GetAsync(Guid deviceId, CancellationToken cancellationToken = default);

    /// <summary>Updates the last successful use timestamp.</summary>
    /// <param name="deviceId">The public device identifier.</param>
    /// <param name="lastUsedAt">The last-used timestamp.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="true" /> when the row was updated.</returns>
    Task<bool> UpdateLastUsedAsync(Guid deviceId, DateTimeOffset lastUsedAt, CancellationToken cancellationToken = default);

    /// <summary>Lists devices for a user and optional tenant scope.</summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted.</param>
    /// <param name="activeOnly">Whether only active devices should be returned.</param>
    /// <param name="now">The timestamp used for active filtering.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The matched devices.</returns>
    Task<IReadOnlyList<RememberedMfaDevice>> ListForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Counts devices for a user and optional tenant scope.</summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted.</param>
    /// <param name="activeOnly">Whether only active devices should be counted.</param>
    /// <param name="now">The timestamp used for active filtering.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The matched device count.</returns>
    Task<int> CountForUserAsync(Guid userId, TenantContext? tenant, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Revokes one device owned by a user.</summary>
    /// <param name="deviceId">The public device identifier.</param>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="revokedAt">The revocation timestamp.</param>
    /// <param name="reason">The revocation reason.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="true" /> when a device was revoked.</returns>
    Task<bool> RevokeAsync(Guid deviceId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);

    /// <summary>Revokes all devices owned by a user.</summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="revokedAt">The revocation timestamp.</param>
    /// <param name="reason">The revocation reason.</param>
    /// <param name="tenant">The tenant scope. A <see langword="null" /> value is unrestricted.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of revoked devices.</returns>
    Task<int> RevokeAllForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default);
}
