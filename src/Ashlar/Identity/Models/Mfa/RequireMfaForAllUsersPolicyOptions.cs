namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Configures an MFA policy that requires factors for every active user.
/// </summary>
public sealed class RequireMfaForAllUsersPolicyOptions
{
    /// <summary>
    /// Factor families required for every active user.
    /// </summary>
    public IList<string> RequiredFactors { get; } = [];

    /// <summary>
    /// Validates global MFA policy options.
    /// </summary>
    /// <param name="options">The options instance to validate.</param>
    /// <returns><see langword="true" /> when at least one non-empty factor is configured.</returns>
    public static bool Validate(RequireMfaForAllUsersPolicyOptions? options)
    {
        return options is not null
            && options.RequiredFactors.Count > 0
            && options.RequiredFactors.All(factor => !string.IsNullOrWhiteSpace(factor));
    }
}
