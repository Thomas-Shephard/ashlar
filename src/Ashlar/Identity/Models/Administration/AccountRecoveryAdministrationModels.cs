namespace Ashlar.Identity.Models.Administration;

/// <summary>
/// Request for administrator account recovery option lookup.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="Tenant">The requested scope. Use <see cref="TenantContext.Global" /> for global users.</param>
/// <param name="IncludeAllTenants">Whether to allow lookup across every scope. Cannot be combined with <paramref name="Tenant" />.</param>
/// <param name="RecentSecurityEventWindow">Optional recent security event window for the embedded account-security posture.</param>
public sealed record AccountRecoveryOptionsRequest(
    Guid UserId,
    TenantContext? Tenant = null,
    bool IncludeAllTenants = false,
    TimeSpan? RecentSecurityEventWindow = null)
{
    /// <summary>
    /// Throws when the account recovery options request is not safe to execute.
    /// </summary>
    /// <param name="request">The recovery options request value.</param>
    public static void ThrowIfInvalid(AccountRecoveryOptionsRequest? request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AdministrationScopeValidation.ThrowIfInvalidScope(request.Tenant, request.IncludeAllTenants);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
    }
}

/// <summary>
/// Display-safe administrator account recovery options for a user account.
/// </summary>
/// <param name="Detail">The target user detail and account-security posture.</param>
/// <param name="Actions">The display-safe destructive action previews.</param>
public sealed record AccountRecoveryOptions(
    UserAdministrationDetail Detail,
    AccountRecoveryActionOptions Actions);

/// <summary>
/// Display-safe destructive action previews for account recovery tooling.
/// </summary>
/// <param name="WouldResetMfa">Whether an MFA reset would remove at least one resettable factor credential or remembered MFA device.</param>
/// <param name="WouldRevokeSessions">Whether session revocation would revoke at least one active session.</param>
/// <param name="RevocableProviderOptions">Display-safe revocable credential provider options.</param>
/// <param name="Warnings">Warnings for destructive operations, such as removing the last primary sign-in method.</param>
public sealed record AccountRecoveryActionOptions(
    bool WouldResetMfa,
    bool WouldRevokeSessions,
    IReadOnlyList<AccountRecoveryProviderOption> RevocableProviderOptions,
    IReadOnlyList<AccountRecoveryWarning> Warnings);

/// <summary>
/// Display-safe credential option that can be revoked by <paramref name="Provider" />.
/// </summary>
/// <param name="Provider">The provider key value.</param>
/// <param name="DisplayName">The display name value.</param>
/// <param name="CredentialCount">The number of revocable credentials for this <paramref name="Provider" />.</param>
/// <param name="PrimaryCredentialCount">The number of revocable primary credentials for this <paramref name="Provider" />.</param>
/// <param name="AdditionalVerificationCredentialCount">The number of revocable additional verification credentials for this <paramref name="Provider" />.</param>
/// <param name="WouldRemoveLastPrimarySignInMethod">Whether revoking this <paramref name="Provider" /> may remove the account's last available primary sign-in method.</param>
public sealed record AccountRecoveryProviderOption(
    AuthenticationProviderKey Provider,
    string DisplayName,
    int CredentialCount,
    int PrimaryCredentialCount,
    int AdditionalVerificationCredentialCount,
    bool WouldRemoveLastPrimarySignInMethod);

/// <summary>
/// Display-safe warning for an account recovery option.
/// </summary>
/// <param name="Code">Stable warning code.</param>
/// <param name="Message">Display-safe warning message.</param>
/// <param name="Provider">Optional provider key associated with the warning.</param>
public sealed record AccountRecoveryWarning(
    string Code,
    string Message,
    AuthenticationProviderKey? Provider = null);
