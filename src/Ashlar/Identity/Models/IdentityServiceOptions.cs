namespace Ashlar.Identity.Models;

/// <summary>
/// Configuration options for the <see cref="Ashlar.Identity.IdentityService"/>.
/// </summary>
public sealed class IdentityServiceOptions
{
    /// <summary>
    /// Gets or sets the minimum time that must elapse between updates to the <c>LastUsedAt</c> timestamp for a credential.
    /// Defaults to 1 minute.
    /// </summary>
    public TimeSpan LastUsedAtUpdateThreshold { get; init; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Gets or sets the duration for which an authentication handshake (MFA) session ticket remains valid.
    /// Defaults to 15 minutes.
    /// </summary>
    public TimeSpan HandshakeExpiry { get; init; } = TimeSpan.FromMinutes(15);
}
