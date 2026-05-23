namespace Ashlar.OAuth;

/// <summary>
/// Describes the outcome of unlinking an external account from the current Ashlar user.
/// </summary>
/// <param name="Status">The unlink outcome status.</param>
/// <param name="AccountSecurityOperation">The underlying account-security operation result, when revocation was attempted.</param>
public sealed record AshlarExternalAccountUnlinkResult(
    AshlarExternalAccountUnlinkStatus Status,
    Result<AccountSecurityOperationResult>? AccountSecurityOperation = null)
{
    /// <summary>
    /// Gets a value indicating whether a credential was unlinked.
    /// </summary>
    public bool Unlinked => Status == AshlarExternalAccountUnlinkStatus.Unlinked;
}

/// <summary>
/// Enumerates safe result states for external account unlinking.
/// </summary>
/// <remarks>
/// Applications should prefer generic user-facing messages for unlink failures and require fresh MFA or
/// equivalent step-up before invoking unlink operations.
/// </remarks>
public enum AshlarExternalAccountUnlinkStatus
{
    /// <summary>
    /// The external account credential was revoked.
    /// </summary>
    Unlinked = 0,

    /// <summary>
    /// The configured provider is not currently linked to the current Ashlar user.
    /// </summary>
    NotLinked = 1,

    /// <summary>
    /// The requested provider is not configured.
    /// </summary>
    UnsupportedProvider = 2,

    /// <summary>
    /// The current Ashlar user could not be found.
    /// </summary>
    UserNotFound = 3,

    /// <summary>
    /// The current Ashlar user does not belong to the requested tenant.
    /// </summary>
    TenantMismatch = 4,

    /// <summary>
    /// Removing this credential would leave the user without a usable primary sign-in method.
    /// </summary>
    WouldRemoveLastSignInMethod = 5,

    /// <summary>
    /// The credential could not be unlinked.
    /// </summary>
    Failed = 6
}
