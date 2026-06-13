namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Configures host-level MFA orchestration behavior for an authentication attempt.
/// </summary>
public sealed record MfaOrchestrationOptions
{
    /// <summary>
    /// Whether policy-required additional verification may be satisfied by a valid remembered MFA device token.
    /// </summary>
    public bool EnableRememberedMfaDevices { get; init; }

    /// <summary>
    /// Claim name used by providers to report factor families they can satisfy.
    /// </summary>
    public string ProviderFactorsClaimName { get; init; } = "mfa_factors";
}
