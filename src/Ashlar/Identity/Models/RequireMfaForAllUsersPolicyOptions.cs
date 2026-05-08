namespace Ashlar.Identity.Models;

/// <summary>
/// Configures an MFA policy that requires factors for every active user.
/// </summary>
public sealed class RequireMfaForAllUsersPolicyOptions
{
    public IList<string> RequiredFactors { get; } = [];

    public static bool Validate(RequireMfaForAllUsersPolicyOptions? options)
    {
        return options is not null
            && options.RequiredFactors.Count > 0
            && options.RequiredFactors.All(factor => !string.IsNullOrWhiteSpace(factor));
    }
}
