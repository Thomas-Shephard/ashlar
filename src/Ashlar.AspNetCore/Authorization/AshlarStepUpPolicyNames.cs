namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Well-known Ashlar ASP.NET Core authorization policy names.
/// </summary>
public static class AshlarStepUpPolicyNames
{
    /// <summary>
    /// Requires a fresh additional verification using the configured defaults.
    /// </summary>
    public const string FreshMfa = "Ashlar.FreshMfa";

    /// <summary>
    /// Requires fresh additional verification when the account has a usable eligible factor.
    /// </summary>
    public const string FreshMfaIfAvailable = "Ashlar.FreshMfaIfAvailable";
}
