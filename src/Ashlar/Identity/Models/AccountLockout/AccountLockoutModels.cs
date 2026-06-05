using Ashlar.Auditing;

namespace Ashlar.Identity.Models.AccountLockout;

/// <summary>
/// Configures automatic per-account lockout after failed primary credential verification.
/// </summary>
public sealed class AccountLockoutOptions
{
    /// <summary>
    /// Gets or sets the failed-attempt threshold that activates lockout.
    /// </summary>
    public int FailureThreshold { get; set; } = 5;

    /// <summary>
    /// Gets or sets how long an automatic lockout remains active.
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Validates account lockout options.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(AccountLockoutOptions? options)
    {
        return options is { FailureThreshold: > 0 } && options.LockoutDuration > TimeSpan.Zero;
    }

    /// <summary>
    /// Throws when the account lockout policy values cannot produce a temporary lockout.
    /// </summary>
    /// <param name="failureThreshold">The failed-attempt threshold that activates lockout.</param>
    /// <param name="lockoutDuration">How long a newly activated lockout remains active.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the threshold or duration is not positive.</exception>
    public static void ThrowIfInvalidPolicy(int failureThreshold, TimeSpan lockoutDuration)
    {
        if (failureThreshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(failureThreshold), failureThreshold, "Failure threshold must be greater than zero.");
        }

        if (lockoutDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lockoutDuration), lockoutDuration, "Lockout duration must be greater than zero.");
        }
    }
}

/// <summary>
/// Durable automatic lockout state for a user and authentication <paramref name="Provider" />.
/// </summary>
/// <param name="UserId">The user that owns the lockout state.</param>
/// <param name="TenantId">The tenant scope for the user, or <see langword="null" /> for global users.</param>
/// <param name="Provider">The authentication provider key.</param>
/// <param name="FailedAttemptCount">The number of recorded failures in the current lockout window.</param>
/// <param name="FirstFailedAt">The first failure timestamp in the current lockout window.</param>
/// <param name="LastFailedAt">The most recent failure timestamp in the current lockout window.</param>
/// <param name="LockedUntil">The automatic lockout expiry timestamp, when locked.</param>
/// <param name="Version">A repository concurrency token.</param>
public sealed record AccountLockoutRecord(
    Guid UserId,
    Guid? TenantId,
    AuthenticationProviderKey Provider,
    int FailedAttemptCount,
    DateTimeOffset FirstFailedAt,
    DateTimeOffset LastFailedAt,
    DateTimeOffset? LockedUntil,
    string Version);

/// <summary>
/// Result of atomically recording a failed credential verification in durable lockout state.
/// </summary>
/// <param name="Record">The updated durable lockout record.</param>
/// <param name="LockoutActivated">Whether this write activated a new automatic lockout.</param>
public sealed record AccountLockoutRecordUpdate(
    AccountLockoutRecord Record,
    bool LockoutActivated);

/// <summary>
/// Current automatic lockout status for a user and <paramref name="Provider" />.
/// </summary>
/// <param name="UserId">The user that owns the lockout state.</param>
/// <param name="TenantId">The tenant scope for the user, or <see langword="null" /> for global users.</param>
/// <param name="Provider">The authentication provider key.</param>
/// <param name="FailedAttemptCount">The number of recorded failures in the current lockout window.</param>
/// <param name="FirstFailedAt">The first failure timestamp in the current lockout window.</param>
/// <param name="LastFailedAt">The most recent failure timestamp in the current lockout window.</param>
/// <param name="LockedUntil">The automatic lockout expiry timestamp, when locked.</param>
/// <param name="IsLockedOut">Whether automatic lockout is active at the time of evaluation.</param>
public sealed record AccountLockoutStatus(
    Guid UserId,
    Guid? TenantId,
    AuthenticationProviderKey Provider,
    int FailedAttemptCount,
    DateTimeOffset? FirstFailedAt,
    DateTimeOffset? LastFailedAt,
    DateTimeOffset? LockedUntil,
    bool IsLockedOut)
{
    /// <summary>
    /// Creates an unlocked empty status.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="tenantId">The tenant id, when scoped.</param>
    /// <param name="provider">The provider key.</param>
    /// <returns>An unlocked status with no failures.</returns>
    public static AccountLockoutStatus None(Guid userId, Guid? tenantId, AuthenticationProviderKey provider)
    {
        return new AccountLockoutStatus(userId, tenantId, provider, 0, null, null, null, false);
    }
}

/// <summary>
/// Result of recording a failed credential verification.
/// </summary>
/// <param name="Status">The updated lockout status.</param>
/// <param name="ThresholdReached">Whether the updated failure count meets or exceeds the configured threshold.</param>
/// <param name="LockoutActivated">Whether this failure activated a new automatic lockout.</param>
public sealed record AccountLockoutFailureResult(
    AccountLockoutStatus Status,
    bool ThresholdReached,
    bool LockoutActivated);

/// <summary>
/// Safe context attached to account lockout operations and security events.
/// </summary>
/// <param name="Audit">Optional safe operation metadata.</param>
/// <param name="Tenant">Optional tenant scope that must match the user.</param>
public sealed record AccountLockoutContext(
    AuditContext? Audit = null,
    TenantContext? Tenant = null);
