namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Represents the mfa policy evaluation data model.
/// </summary>
/// <param name="IsMfaRequired">The is mfa required value.</param>
/// <param name="Requirement">The requirement value.</param>
public sealed record MfaPolicyEvaluation(bool IsMfaRequired, MfaRequirement? Requirement = null);
