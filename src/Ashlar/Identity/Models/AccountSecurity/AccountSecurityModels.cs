using Ashlar.Auditing;

namespace Ashlar.Identity.Models.AccountSecurity;

/// <summary>Context supplied to account-state business-policy guards.</summary>
public record AccountSecurityGuardContext
{
    /// <summary>Creates business-policy context for an authorized account-state change.</summary>
    /// <param name="Audit">Audit metadata for the operation.</param>
    /// <param name="Tenant">The explicit target <paramref name="Tenant" /> or global scope.</param>
    /// <param name="Reason">An optional display-safe reason.</param>
    /// <param name="IncludeAllTenants">Whether the target lookup crosses all <paramref name="Tenant" /> scopes.</param>
    public AccountSecurityGuardContext(
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

    /// <summary>Gets the operation audit metadata.</summary>
    public AuditContext Audit { get; }

    /// <summary>Gets the explicit target tenant or global scope.</summary>
    public TenantContext? Tenant { get; }

    /// <summary>Gets the optional display-safe reason.</summary>
    public string? Reason { get; }

    /// <summary>Gets whether the target lookup crosses all tenant scopes.</summary>
    public bool IncludeAllTenants { get; }

    internal void ThrowIfInvalidScope()
    {
        AdministrationScopeValidation.ThrowIfInvalidScope(Tenant, IncludeAllTenants);
    }
}

internal sealed record SetUserAccountStateRequest : AccountSecurityOperationRequest
{
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

    public UserAccountState AccountState { get; }

    public bool RevokeSessionsAndRememberedMfaDevices { get; }
}

internal record AccountSecurityOperationRequest(
    AuditContext Audit,
    TenantContext? Tenant = null,
    string? Reason = null,
    bool IncludeAllTenants = false,
    bool PreservePrimarySignInMethod = false)
    : AccountSecurityGuardContext(Audit, Tenant, Reason, IncludeAllTenants);

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

internal record AccountSecurityPostureRequest(
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
