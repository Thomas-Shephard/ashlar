using Ashlar.Identity.Models;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// Options for Ashlar ASP.NET Core step-up authorization policies.
/// </summary>
public sealed class AshlarStepUpOptions
{
    /// <summary>
    /// Gets or sets the default maximum age for additional verification.
    /// </summary>
    public TimeSpan FreshnessWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets the default allowed additional verification providers.
    /// </summary>
    public HashSet<AuthenticationProviderKey> AllowedProviders { get; } = [];

    /// <summary>
    /// Gets the default allowed additional verification factors.
    /// </summary>
    public HashSet<string> AllowedFactors { get; } = new(StringComparer.OrdinalIgnoreCase);
}
