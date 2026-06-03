namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Manages remembered MFA devices without treating them as credentials or authentication factors.
/// </summary>
public interface IRememberedMfaDeviceService
{
    /// <summary>
    /// Creates a remembered MFA device and returns the raw token once.
    /// </summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="request">The creation request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The creation result.</returns>
    Task<Result<RememberedMfaDeviceCreated>> CreateAsync(Guid userId, CreateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a raw remembered MFA device token for the supplied user context.
    /// </summary>
    /// <param name="userId">The expected owning user identifier.</param>
    /// <param name="request">The validation request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The validation result.</returns>
    Task<ValidateRememberedMfaDeviceResult> ValidateAsync(Guid userId, ValidateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists safe remembered MFA device metadata for a user.
    /// </summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="request">The list request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The safe device summaries.</returns>
    Task<IReadOnlyList<RememberedMfaDeviceSummary>> ListAsync(Guid userId, ListRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a single remembered MFA device owned by a user.
    /// </summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="request">The revocation request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="true" /> when a device was revoked.</returns>
    Task<bool> RevokeAsync(Guid userId, RevokeRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all remembered MFA devices for a user.
    /// </summary>
    /// <param name="userId">The owning user identifier.</param>
    /// <param name="request">The revocation request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The number of revoked devices.</returns>
    Task<int> RevokeAllAsync(Guid userId, RevokeAllRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default);
}
