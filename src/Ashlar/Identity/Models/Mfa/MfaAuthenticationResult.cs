namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Lists the outcomes of an MFA-aware authentication flow.
/// </summary>
public enum MfaAuthenticationStatus
{
    /// <summary>
    /// Authentication failed.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Authentication completed successfully and the host may issue or continue an application session.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Primary authentication succeeded, but the host must complete MFA before issuing a full session.
    /// </summary>
    MfaRequired = 2,
    /// <summary>
    /// The MFA handshake exists, but not all required factors have been verified.
    /// </summary>
    HandshakeIncomplete = 3,
    /// <summary>
    /// Authentication was blocked by a rate limiter. Treat the result as a failed authentication attempt.
    /// </summary>
    RateLimited = 4
}

/// <summary>
/// Result returned by MFA-aware authentication flows.
/// </summary>
/// <param name="Status">Outcome of the MFA-aware authentication flow.</param>
/// <param name="User">The authenticated user when authentication succeeds.</param>
/// <param name="HandshakeToken">The raw handshake token when more MFA factors are required. Do not log or persist this value.</param>
/// <param name="RequiredFactors">The MFA factors still required for the handshake.</param>
/// <param name="Claims">Additional claims produced by the authentication provider.</param>
/// <param name="ErrorMessage">A generic, display-safe error message when authentication fails.</param>
/// <param name="FreshMfaSatisfied">Whether this result came from a fresh MFA ceremony suitable for step-up decisions. This public signal is not proof for remembered-device token issuance.</param>
/// <param name="CredentialUpdatePersisted">Whether all provider-requested credential data changes were actually persisted during authentication.</param>
public sealed record MfaAuthenticationResult(
    MfaAuthenticationStatus Status,
    IUser? User = null,
    string? HandshakeToken = null,
    IEnumerable<string>? RequiredFactors = null,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims = null,
    string? ErrorMessage = null,
    bool FreshMfaSatisfied = false,
    bool CredentialUpdatePersisted = false)
{
    /// <summary>
    /// Creates an MFA authentication result from single-value provider claims.
    /// </summary>
    /// <param name="status">Outcome of the MFA-aware authentication flow.</param>
    /// <param name="user">The authenticated user when authentication succeeds.</param>
    /// <param name="handshakeToken">The raw handshake token when more MFA factors are required. Do not log or persist this value.</param>
    /// <param name="requiredFactors">The MFA factors still required for the handshake.</param>
    /// <param name="claims">Additional single-value claims produced by the authentication provider.</param>
    /// <param name="errorMessage">A generic, display-safe error message when authentication fails.</param>
    /// <param name="freshMfaSatisfied">Whether this result came from a fresh MFA ceremony suitable for step-up decisions.</param>
    /// <param name="credentialUpdatePersisted">Whether all provider-requested credential data changes were actually persisted during authentication.</param>
    public MfaAuthenticationResult(
        MfaAuthenticationStatus status,
        IUser? user,
        string? handshakeToken,
        IEnumerable<string>? requiredFactors,
        IDictionary<string, string>? claims,
        string? errorMessage = null,
        bool freshMfaSatisfied = false,
        bool credentialUpdatePersisted = false)
        : this(status, user, handshakeToken, requiredFactors, AuthenticationClaims.FromSingleValues(claims), errorMessage, freshMfaSatisfied, credentialUpdatePersisted)
    {
    }

    internal FreshMfaProof? RememberedDeviceCreationProof { get; init; }

    internal bool CanCreateRememberedMfaDevice => FreshMfaSatisfied && RememberedDeviceCreationProof != null;

    internal AuthenticationSessionIssuanceProof? SessionIssuanceProof { get; init; }

    internal bool CanIssueAuthenticationSession => Status == MfaAuthenticationStatus.Succeeded && HasUserId(User) && SessionIssuanceProof != null;

    internal IUser? AuthenticationSessionIssuanceUser => CanIssueAuthenticationSession ? User : null;

    internal StepUpSessionMarkingProof? StepUpSessionMarkingProof { get; init; }

    internal bool CanMarkSessionStepUpVerified => Status == MfaAuthenticationStatus.Succeeded && HasUserId(User) && FreshMfaSatisfied && StepUpSessionMarkingProof != null;

    internal IUser? StepUpVerifiedUser => CanMarkSessionStepUpVerified ? User : null;

    private static bool HasUserId(IUser? user)
    {
        return user != null && user.Id != Guid.Empty;
    }
}

internal sealed class FreshMfaProof
{
    internal static FreshMfaProof Instance { get; } = new();

    private FreshMfaProof()
    {
    }
}

internal sealed class AuthenticationSessionIssuanceProof
{
    internal static AuthenticationSessionIssuanceProof Instance { get; } = new();

    private AuthenticationSessionIssuanceProof()
    {
    }
}

internal sealed class StepUpSessionMarkingProof
{
    internal static StepUpSessionMarkingProof Instance { get; } = new();

    private StepUpSessionMarkingProof()
    {
    }
}
