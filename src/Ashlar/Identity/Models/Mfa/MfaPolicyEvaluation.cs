namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Describes whether the current authentication flow requires MFA.
/// </summary>
/// <param name="IsMfaRequired">Whether the host application must orchestrate a secondary factor before issuing a session.</param>
/// <param name="Requirement">Details about the required factors, when MFA is required.</param>
public sealed record MfaPolicyEvaluation(bool IsMfaRequired, MfaRequirement? Requirement = null);
