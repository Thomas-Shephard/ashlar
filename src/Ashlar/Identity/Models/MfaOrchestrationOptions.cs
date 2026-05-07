namespace Ashlar.Identity.Models;

public sealed record MfaOrchestrationOptions
{
    public string ProviderFactorsClaimName { get; init; } = "mfa_factors";
}
