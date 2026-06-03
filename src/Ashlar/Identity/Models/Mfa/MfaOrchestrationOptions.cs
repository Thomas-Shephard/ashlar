namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Represents the mfa orchestration options data model.
/// </summary>
public sealed record MfaOrchestrationOptions
{
    /// <summary>
    /// Gets or sets whether routine policy-required MFA may be satisfied by a valid remembered MFA device token.
    /// </summary>
    public bool EnableRememberedMfaDevices { get; init; }

    /// <summary>
    /// Gets or sets the provider factors claim name value.
    /// </summary>
    public string ProviderFactorsClaimName { get; init; } = "mfa_factors";
}
