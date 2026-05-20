namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Represents the mfa requirement data model.
/// </summary>
/// <param name="RequiredFactors">The required factors value.</param>
public sealed record MfaRequirement(IEnumerable<string> RequiredFactors);
