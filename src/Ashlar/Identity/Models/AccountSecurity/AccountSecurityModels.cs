using Ashlar.Auditing;

namespace Ashlar.Identity.Models.AccountSecurity;

/// <summary>
/// Request metadata for administrator account-security operations.
/// </summary>
public record AccountSecurityOperationRequest
{
    /// <summary>
    /// Initializes account-security operation metadata and validates that its <paramref name="Tenant" /> scope is explicit.
    /// </summary>
    /// <param name="Audit">Audit metadata recorded with the account-security operation.</param>
    /// <param name="Tenant">Scope for the target user. Use <see cref="TenantContext.Global" /> for global users.</param>
    /// <param name="Reason">Optional provider-neutral, display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</param>
    /// <param name="IncludeAllTenants">Whether to remove scope filtering for the specified user. Cannot be combined with <paramref name="Tenant" />.</param>
    public AccountSecurityOperationRequest(
        AuditContext Audit,
        TenantContext? Tenant = null,
        string? Reason = null,
        bool IncludeAllTenants = false)
    {
        this.Audit = Audit ?? throw new ArgumentNullException(nameof(Audit), "Admin account security operations require audit metadata.");
        this.Tenant = Tenant;
        this.Reason = Reason;
        this.IncludeAllTenants = IncludeAllTenants;
        ThrowIfInvalidScope();
    }

    /// <summary>Audit metadata recorded with the account-security operation.</summary>
    public AuditContext Audit { get; }

    /// <summary>Tenant scope for the target user, or <see langword="null" /> when <see cref="IncludeAllTenants" /> is enabled.</summary>
    public TenantContext? Tenant { get; }

    /// <summary>Optional provider-neutral, display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</summary>
    public string? Reason { get; }

    /// <summary>Whether scope filtering is removed for the specified user.</summary>
    public bool IncludeAllTenants { get; }

    /// <summary>
    /// Throws when the request does not identify exactly one mutation scope.
    /// </summary>
    public void ThrowIfInvalidScope()
    {
        AdministrationScopeValidation.ThrowIfInvalidScope(Tenant, IncludeAllTenants);
    }
}

/// <summary>
/// Request metadata for changing a user's account state.
/// </summary>
public sealed record SetUserAccountStateRequest : AccountSecurityOperationRequest
{
    /// <summary>
    /// Initializes account-state change metadata and validates that its <paramref name="Tenant" /> scope is explicit.
    /// </summary>
    /// <param name="AccountState">State to apply to the target account.</param>
    /// <param name="Audit">Audit metadata recorded with the account-state operation.</param>
    /// <param name="Tenant">Scope for the target user. Use <see cref="TenantContext.Global" /> for global users.</param>
    /// <param name="Reason">Optional provider-neutral, display-safe reason recorded with revocation and security events. Do not include secrets, tokens, or credentials.</param>
    /// <param name="RevokeSessionsAndRememberedMfaDevices">Whether transitions to non-active states revoke active sessions and remembered MFA devices.</param>
    /// <param name="IncludeAllTenants">Whether to remove scope filtering for the specified user. Cannot be combined with <paramref name="Tenant" />.</param>
    public SetUserAccountStateRequest(
        UserAccountState AccountState,
        AuditContext Audit,
        TenantContext? Tenant = null,
        string? Reason = null,
        bool RevokeSessionsAndRememberedMfaDevices = true,
        bool IncludeAllTenants = false)
        : base(Audit, Tenant, Reason, IncludeAllTenants)
    {
        this.AccountState = AccountState;
        this.RevokeSessionsAndRememberedMfaDevices = RevokeSessionsAndRememberedMfaDevices;
    }

    /// <summary>Account state to apply to the target account.</summary>
    public UserAccountState AccountState { get; }

    /// <summary>Whether transitions to non-active states revoke active sessions and remembered MFA devices.</summary>
    public bool RevokeSessionsAndRememberedMfaDevices { get; }
}

/// <summary>
/// Result counts from an administrator account security operation.
/// </summary>
/// <param name="UserId">Affected user identifier.</param>
/// <param name="UserChanged">Whether the user row was updated.</param>
/// <param name="SessionsRevoked">The number of active sessions revoked.</param>
/// <param name="CredentialsRevoked">The number of credentials revoked.</param>
/// <param name="PreviousState">The account state before the operation, when applicable.</param>
/// <param name="CurrentState">The account state after the operation, when applicable.</param>
/// <param name="RememberedMfaDevicesRevoked">The number of remembered MFA devices revoked.</param>
public sealed record AccountSecurityOperationResult(
    Guid UserId,
    bool UserChanged = false,
    int SessionsRevoked = 0,
    int CredentialsRevoked = 0,
    UserAccountState? PreviousState = null,
    UserAccountState? CurrentState = null,
    int RememberedMfaDevicesRevoked = 0);

/// <summary>
/// Request metadata for an account-security posture lookup.
/// </summary>
/// <param name="Tenant">Tenant scope that must match the inspected user. Use <see cref="TenantContext.Global" /> for global users; this request does not use <see langword="null" /> as an all-scope lookup.</param>
/// <param name="RecentSecurityEventWindow">Optional window used to count recent security events.</param>
public record AccountSecurityPostureRequest(
    TenantContext? Tenant = null,
    TimeSpan? RecentSecurityEventWindow = null);

/// <summary>
/// Describes how an account credential participates in sign-in and additional verification.
/// </summary>
public enum CredentialPosturePurpose
{
    /// <summary>
    /// The credential can be used as a primary sign-in method.
    /// </summary>
    Primary = 0,

    /// <summary>
    /// The credential can satisfy additional verification.
    /// </summary>
    AdditionalVerification = 1,

    /// <summary>
    /// The credential has an unknown or custom purpose.
    /// </summary>
    Unknown = 2
}

/// <summary>
/// Safe account credential inventory item.
/// </summary>
/// <param name="CredentialId">Stable credential identifier.</param>
/// <param name="Provider">Provider key for the credential.</param>
/// <param name="DisplayName">Display-safe credential label.</param>
/// <param name="Purpose">How the credential participates in sign-in or additional verification.</param>
/// <param name="FactorType">Additional verification factor family satisfied by the credential, when applicable.</param>
/// <param name="IsPrimaryCredential">Whether this is a primary credential.</param>
/// <param name="IsAdditionalVerificationFactor">Whether this can satisfy additional verification.</param>
/// <param name="IsAvailable">Whether this credential is active and unexpired.</param>
/// <param name="IsRevocable">Whether this credential can be revoked.</param>
/// <param name="IsResettable">Whether this credential can be reset by MFA reset operations.</param>
/// <param name="CreatedAt">UTC time when the credential was created.</param>
/// <param name="LastUsedAt">UTC time when the credential last authenticated successfully, when known.</param>
/// <param name="ExpiresAt">Credential expiration time, when one is set.</param>
/// <param name="Status">Current credential lifecycle status.</param>
public sealed record CredentialPostureItem(
    Guid CredentialId,
    AuthenticationProviderKey Provider,
    string DisplayName,
    CredentialPosturePurpose Purpose,
    string? FactorType,
    bool IsPrimaryCredential,
    bool IsAdditionalVerificationFactor,
    bool IsAvailable,
    bool IsRevocable,
    bool IsResettable,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? ExpiresAt,
    CredentialStatus Status);

/// <summary>
/// Describes a configured additional verification factor family.
/// </summary>
/// <param name="FactorType">Additional verification factor family.</param>
/// <param name="DisplayName">Display-safe factor label.</param>
/// <param name="IsConfigured">Whether this factor is configured.</param>
/// <param name="IsUsable">Whether this factor has at least one usable credential.</param>
/// <param name="Providers">Authentication provider keys backing this factor.</param>
public sealed record AdditionalVerificationFactorPosture(
    string FactorType,
    string DisplayName,
    bool IsConfigured,
    bool IsUsable,
    IReadOnlyList<AuthenticationProviderKey> Providers);

/// <summary>
/// Describes the MFA and step-up policy posture for an account.
/// </summary>
/// <param name="IsAdditionalVerificationRequired">Whether policy requires additional verification.</param>
/// <param name="RequiredFactorTypes">Factor families that policy requires.</param>
/// <param name="AllowedFactorTypes">Factor families that may satisfy policy.</param>
/// <param name="HasUsableAdditionalVerificationFactor">Whether any usable additional verification factor exists.</param>
/// <param name="IsReadyForAdditionalVerification">Whether the user can satisfy the current policy.</param>
/// <param name="MissingRequiredFactorTypes">Required factor families the account cannot currently satisfy.</param>
/// <param name="MissingRequiredFactorDisplayNames">Display-safe names for missing required factors.</param>
/// <param name="IsLockedOutByPolicy">Whether policy currently prevents sign-in completion.</param>
public sealed record AccountSecurityPolicyPosture(
    bool IsAdditionalVerificationRequired,
    IReadOnlyList<string> RequiredFactorTypes,
    IReadOnlyList<string> AllowedFactorTypes,
    bool HasUsableAdditionalVerificationFactor,
    bool IsReadyForAdditionalVerification,
    IReadOnlyList<string> MissingRequiredFactorTypes,
    IReadOnlyList<string> MissingRequiredFactorDisplayNames,
    bool IsLockedOutByPolicy);

/// <summary>
/// Non-secret account-security posture details for a user account.
/// </summary>
/// <param name="UserId">User whose posture is described.</param>
/// <param name="AccountState">Current account state that controls sign-in eligibility.</param>
/// <param name="IsEmailVerified">Whether the email address is verified.</param>
/// <param name="CanSignIn">Whether the account can sign in under current credential and <paramref name="Policy" /> state.</param>
/// <param name="PrimaryCredentials">Display-safe primary credentials configured for the account.</param>
/// <param name="AdditionalVerificationFactors">Display-safe additional verification factors configured for the account.</param>
/// <param name="Policy">The current policy posture.</param>
/// <param name="CredentialInventory">The display-safe credential inventory, excluding secrets and provider raw identifiers.</param>
/// <param name="ActiveSessionCount">Number of currently active application sessions.</param>
/// <param name="RecentSecurityEventCount">Number of security events in the requested recent-event window, when available.</param>
public record AccountSecurityPosture(
    Guid UserId,
    UserAccountState AccountState,
    bool IsEmailVerified,
    bool CanSignIn,
    IReadOnlyList<CredentialPostureItem> PrimaryCredentials,
    IReadOnlyList<AdditionalVerificationFactorPosture> AdditionalVerificationFactors,
    AccountSecurityPolicyPosture Policy,
    IReadOnlyList<CredentialPostureItem> CredentialInventory,
    int ActiveSessionCount,
    int? RecentSecurityEventCount)
{
    /// <summary>
    /// Gets whether at least one additional verification factor is configured.
    /// </summary>
    public bool IsMfaConfigured => AdditionalVerificationFactors.Any(factor => factor.IsConfigured);

    /// <summary>
    /// Gets the configured credential provider keys represented in the display-safe inventory.
    /// </summary>
    /// <returns>The configured credential provider keys.</returns>
    public IReadOnlyList<AuthenticationProviderKey> GetConfiguredCredentials()
    {
        return CredentialInventory
            .Select(item => item.Provider)
            .Distinct()
            .OrderBy(provider => provider.Type.Value, StringComparer.Ordinal)
            .ThenBy(provider => provider.Name, StringComparer.Ordinal)
            .ToArray();
    }
}

/// <summary>
/// Optional read model for stores that can efficiently count security events.
/// </summary>
public interface IUserSecurityEventSummaryRepository
{
    /// <summary>
    /// Counts recent security events for a user.
    /// </summary>
    /// <param name="userId">User whose security events should be counted.</param>
    /// <param name="since">Inclusive lower timestamp bound for recent events.</param>
    /// <param name="cancellationToken">Token for aborting the count query.</param>
    /// <returns>The number of matching security events.</returns>
    Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default);
}
