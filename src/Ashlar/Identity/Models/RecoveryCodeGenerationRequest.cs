namespace Ashlar.Identity;

/// <summary>
/// Represents a request to generate new recovery codes.
/// </summary>
public sealed record RecoveryCodeGenerationRequest
{
    /// <summary>
    /// Gets or sets a value indicating whether existing recovery codes should be revoked before generating new ones.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool ReplaceExisting { get; init; } = true;

    /// <summary>
    /// Gets or sets the number of codes to generate. If null, the configured default in <see cref="RecoveryCodeOptions"/> is used.
    /// </summary>
    public int? CodeCount { get; init; }

    /// <summary>
    /// Gets or sets the duration after which the codes expire. If null, the configured default in <see cref="RecoveryCodeOptions"/> is used.
    /// </summary>
    public TimeSpan? ExpiresAfter { get; init; }
}
