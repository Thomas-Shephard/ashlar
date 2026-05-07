namespace Ashlar.Identity.Models;

public sealed record MfaPolicyEvaluation(bool IsMfaRequired, MfaRequirement? Requirement = null);
