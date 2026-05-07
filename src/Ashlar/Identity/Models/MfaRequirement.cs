namespace Ashlar.Identity.Models;

public sealed record MfaRequirement(IEnumerable<string> RequiredFactors);
