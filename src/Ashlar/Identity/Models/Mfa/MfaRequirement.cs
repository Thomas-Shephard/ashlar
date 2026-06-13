namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Lists secondary factor types required for the current authentication flow.
/// </summary>
/// <param name="RequiredFactors">Provider-neutral factor type identifiers that must be verified.</param>
public sealed record MfaRequirement(IEnumerable<string> RequiredFactors);
