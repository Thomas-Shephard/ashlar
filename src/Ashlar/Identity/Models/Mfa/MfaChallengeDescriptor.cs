namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Describes an MFA factor the user can complete.
/// </summary>
/// <param name="FactorType">The provider-specific factor type, such as <c>totp</c> or <c>recovery_code</c>.</param>
/// <param name="Description">Optional display text for the challenge.</param>
public sealed record MfaChallengeDescriptor(string FactorType, string? Description = null);





