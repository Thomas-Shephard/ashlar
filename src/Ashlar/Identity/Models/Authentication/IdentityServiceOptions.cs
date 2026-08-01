namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Configuration options for identity authentication flows.
/// </summary>
public sealed class IdentityServiceOptions
{
    /// <summary>
    /// Minimum time that must elapse between updates to the <c>LastUsedAt</c> timestamp for a credential.
    /// Defaults to 1 minute and cannot be negative.
    /// </summary>
    public TimeSpan LastUsedAtUpdateThreshold { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Determines whether the supplied options are valid.</summary>
    /// <param name="options">Options instance to validate.</param>
    /// <returns><see langword="true" /> when the options are valid; otherwise <see langword="false" />.</returns>
    public static bool Validate(IdentityServiceOptions? options) => options?.LastUsedAtUpdateThreshold >= TimeSpan.Zero;
}
