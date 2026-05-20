using Microsoft.AspNetCore.Authorization;

namespace Ashlar.AspNetCore.Authorization;

/// <summary>
/// An ASP.NET Core authorization requirement that requires fresh Ashlar additional verification.
/// </summary>
public sealed class AshlarStepUpRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarStepUpRequirement"/> class.
    /// </summary>
    /// <param name="freshnessWindow">The maximum age of the additional verification.</param>
    /// <param name="allowedProviders">The optional allowed additional verification providers.</param>
    /// <param name="allowedFactors">The optional allowed additional verification factors.</param>
    /// <param name="mode">The step-up enforcement mode.</param>
    public AshlarStepUpRequirement(
        TimeSpan freshnessWindow,
        IEnumerable<AuthenticationProviderKey>? allowedProviders = null,
        IEnumerable<string>? allowedFactors = null,
        AshlarStepUpMode mode = AshlarStepUpMode.Required)
    {
        if (freshnessWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(freshnessWindow), freshnessWindow, "Freshness window must be positive.");
        }

        FreshnessWindow = freshnessWindow;
        AllowedProviders = allowedProviders?.ToArray() ?? [];
        AllowedFactors = allowedFactors?.Where(f => !string.IsNullOrWhiteSpace(f)).Select(f => f.Trim()).ToArray() ?? [];
        Mode = mode;
    }

    /// <summary>
    /// Gets the maximum age of the additional verification.
    /// </summary>
    public TimeSpan FreshnessWindow { get; }

    /// <summary>
    /// Gets the allowed additional verification providers.
    /// </summary>
    public IReadOnlyCollection<AuthenticationProviderKey> AllowedProviders { get; }

    /// <summary>
    /// Gets the allowed additional verification factors.
    /// </summary>
    public IReadOnlyCollection<string> AllowedFactors { get; }

    /// <summary>
    /// Gets the step-up enforcement mode.
    /// </summary>
    public AshlarStepUpMode Mode { get; }
}
