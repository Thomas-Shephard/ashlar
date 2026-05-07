namespace Ashlar.Identity.Models;

public sealed record MfaChallengeDescriptor(string FactorType, string? Description = null);
