namespace Ashlar.Identity.Models;

/// <summary>
/// Represents the mfa challenge descriptor data model.
/// </summary>
/// <param name="FactorType">The factor type value.</param>
/// <param name="Description">The description value.</param>
public sealed record MfaChallengeDescriptor(string FactorType, string? Description = null);
