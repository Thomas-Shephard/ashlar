namespace Ashlar.Identity.Models.Mfa;

/// <summary>
/// Configures an MFA policy that requires factors for every active user.
/// </summary>
public sealed class RequireMfaForAllUsersPolicyOptions
{
    /// <summary>
    /// Gets or sets the required factors value.
    /// </summary>
    public IList<string> RequiredFactors { get; } = [];

    /// <summary>
    /// Performs the validate operation and returns the result.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns>The operation result.</returns>
    public static bool Validate(RequireMfaForAllUsersPolicyOptions? options)
    {
        return options is not null
            && options.RequiredFactors.Count > 0
            && options.RequiredFactors.All(factor => !string.IsNullOrWhiteSpace(factor));
    }
}





