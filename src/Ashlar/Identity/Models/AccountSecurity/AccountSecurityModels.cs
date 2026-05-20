using Ashlar.Auditing;

namespace Ashlar.Identity.Models.AccountSecurity;

/// <summary>
/// Request metadata for administrator account security operations.
/// </summary>
/// <param name="Audit">The audit context value.</param>
/// <param name="Tenant">The tenant context value.</param>
/// <param name="Reason">The reason value.</param>
public sealed record AccountSecurityOperationRequest(
    AuditContext Audit,
    TenantContext? Tenant = null,
    string? Reason = null);

/// <summary>
/// Result counts from an administrator account security operation.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="UserChanged">The user changed value.</param>
/// <param name="SessionsRevoked">The sessions revoked value.</param>
/// <param name="CredentialsRevoked">The credentials revoked value.</param>
public sealed record AccountSecurityOperationResult(
    Guid UserId,
    bool UserChanged = false,
    int SessionsRevoked = 0,
    int CredentialsRevoked = 0);

/// <summary>
/// Request metadata for a user security posture lookup.
/// </summary>
/// <param name="Tenant">The tenant context value.</param>
/// <param name="RecentSecurityEventWindow">The recent security event window value.</param>
public record AccountSecurityPostureRequest(
    TenantContext? Tenant = null,
    TimeSpan? RecentSecurityEventWindow = null);

/// <summary>
/// Compatibility alias for account security posture lookups.
/// </summary>
/// <param name="Tenant">The tenant context value.</param>
/// <param name="RecentSecurityEventWindow">The recent security event window value.</param>
public sealed record UserSecurityPostureRequest(
    TenantContext? Tenant = null,
    TimeSpan? RecentSecurityEventWindow = null) : AccountSecurityPostureRequest(Tenant, RecentSecurityEventWindow);

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
/// <param name="CredentialId">The credential id value.</param>
/// <param name="Provider">The provider key value.</param>
/// <param name="DisplayName">The display name value.</param>
/// <param name="Purpose">The posture purpose value.</param>
/// <param name="FactorType">The additional verification factor type value.</param>
/// <param name="IsPrimaryCredential">Whether this is a primary credential.</param>
/// <param name="IsAdditionalVerificationFactor">Whether this can satisfy additional verification.</param>
/// <param name="IsAvailable">Whether this credential is active and unexpired.</param>
/// <param name="IsRevocable">Whether this credential can be revoked.</param>
/// <param name="IsResettable">Whether this credential can be reset by MFA reset operations.</param>
/// <param name="CreatedAt">The credential creation time.</param>
/// <param name="LastUsedAt">The last successful use time.</param>
/// <param name="ExpiresAt">The expiration time value.</param>
/// <param name="Status">The lifecycle status value.</param>
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
/// <param name="FactorType">The factor type value.</param>
/// <param name="DisplayName">The display name value.</param>
/// <param name="IsConfigured">Whether this factor is configured.</param>
/// <param name="IsUsable">Whether this factor has at least one usable credential.</param>
/// <param name="Providers">The provider keys backing this factor.</param>
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
/// <param name="RequiredFactorTypes">The required factor type values.</param>
/// <param name="AllowedFactorTypes">The allowed factor type values.</param>
/// <param name="HasUsableAdditionalVerificationFactor">Whether any usable additional verification factor exists.</param>
/// <param name="IsReadyForAdditionalVerification">Whether the user can satisfy the current policy.</param>
/// <param name="MissingRequiredFactorTypes">The missing required factor type values.</param>
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
/// Non-secret account security posture details for a user.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="IsActive">Whether the user is active.</param>
/// <param name="IsEmailVerified">Whether the email address is verified.</param>
/// <param name="CanSignIn">Whether the account can sign in under current credential and <paramref name="Policy" /> state.</param>
/// <param name="PrimaryCredentials">The configured primary credentials.</param>
/// <param name="AdditionalVerificationFactors">The configured additional verification factors.</param>
/// <param name="Policy">The current policy posture.</param>
/// <param name="CredentialInventory">The readable safe credential inventory.</param>
/// <param name="ActiveSessionCount">The active session count.</param>
/// <param name="RecentSecurityEventCount">The recent security event count.</param>
public record AccountSecurityPosture(
    Guid UserId,
    bool IsActive,
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
    /// Gets the configured credential providers for older consumers that only need provider identity.
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
/// Compatibility alias for account security posture results.
/// </summary>
/// <param name="UserId">The user id value.</param>
/// <param name="IsActive">Whether the user is active.</param>
/// <param name="IsEmailVerified">Whether the email address is verified.</param>
/// <param name="CanSignIn">Whether the account can sign in under current credential and <paramref name="Policy" /> state.</param>
/// <param name="PrimaryCredentials">The configured primary credentials.</param>
/// <param name="AdditionalVerificationFactors">The configured additional verification factors.</param>
/// <param name="Policy">The current policy posture.</param>
/// <param name="CredentialInventory">The readable safe credential inventory.</param>
/// <param name="ActiveSessionCount">The active session count.</param>
/// <param name="RecentSecurityEventCount">The recent security event count.</param>
public sealed record UserSecurityPosture(
    Guid UserId,
    bool IsActive,
    bool IsEmailVerified,
    bool CanSignIn,
    IReadOnlyList<CredentialPostureItem> PrimaryCredentials,
    IReadOnlyList<AdditionalVerificationFactorPosture> AdditionalVerificationFactors,
    AccountSecurityPolicyPosture Policy,
    IReadOnlyList<CredentialPostureItem> CredentialInventory,
    int ActiveSessionCount,
    int? RecentSecurityEventCount)
    : AccountSecurityPosture(
        UserId,
        IsActive,
        IsEmailVerified,
        CanSignIn,
        PrimaryCredentials,
        AdditionalVerificationFactors,
        Policy,
        CredentialInventory,
        ActiveSessionCount,
        RecentSecurityEventCount);

/// <summary>
/// Optional read model for stores that can efficiently count security events.
/// </summary>
public interface IUserSecurityEventSummaryRepository
{
    /// <summary>
    /// Counts recent security events for a user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="since">The since value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> CountSecurityEventsForUserAsync(Guid userId, DateTimeOffset since, CancellationToken cancellationToken = default);
}
