namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Configuration options for authentication session lifecycle operations.
/// </summary>
public sealed class AuthenticationSessionOptions
{
    /// <summary>
    /// Default session lifetime. Defaults to 14 days.
    /// </summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Minimum elapsed time before updating <see cref="AuthenticationSession.LastSeenAt"/>.
    /// Defaults to 5 minutes.
    /// </summary>
    public TimeSpan LastSeenUpdateThreshold { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Number of random bytes used to generate raw session tokens. Defaults to 32.
    /// </summary>
    public int TokenByteLength { get; set; } = 32;

    /// <summary>
    /// Whether session IP addresses are persisted when supplied. Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool StoreIpAddress { get; set; } = true;

    /// <summary>
    /// Whether session user agents are persisted when supplied. Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool StoreUserAgent { get; set; } = true;

    /// <summary>
    /// Whether session metadata is persisted when supplied. Defaults to <c><see langword="true" /></c>.
    /// </summary>
    public bool StoreMetadata { get; set; } = true;

    /// <summary>
    /// Maximum accepted IP address length. Defaults to 45 characters.
    /// </summary>
    public int MaxIpAddressLength { get; set; } = 45;

    /// <summary>
    /// Maximum accepted user agent length. Defaults to 512 characters.
    /// </summary>
    public int MaxUserAgentLength { get; set; } = 512;

    /// <summary>
    /// Maximum accepted metadata length. Defaults to 8192 characters.
    /// </summary>
    public int MaxMetadataLength { get; set; } = 8192;
}
