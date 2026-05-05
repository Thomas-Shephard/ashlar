using Ashlar.Identity.Models;

namespace Ashlar.Identity;

/// <summary>
/// Options for recovery code generation and authentication.
/// </summary>
public sealed record RecoveryCodeOptions
{
    /// <summary>
    /// Gets or sets the number of recovery codes to generate. Defaults to 10.
    /// </summary>
    public int CodeCount { get; set; } = 10;

    /// <summary>
    /// Gets or sets the length of the secret portion of each recovery code (excluding the 5-character ID prefix and group separators). Defaults to 12.
    /// </summary>
    public int CodeLength { get; set; } = 12;

    /// <summary>
    /// Gets or sets the size of each character group in the recovery code. Defaults to 4.
    /// </summary>
    public int GroupSize { get; set; } = 4;

    /// <summary>
    /// Gets or sets the duration after which the recovery codes expire.
    /// </summary>
    public TimeSpan? ExpiresAfter { get; set; }

    /// <summary>
    /// Gets or sets the authentication provider key for recovery codes.
    /// </summary>
    public AuthenticationProviderKey ProviderKey { get; set; } = new(ProviderType.RecoveryCode, "RecoveryCode");
}
