namespace Ashlar.Identity.Models.Sessions;

/// <summary>
/// Configuration options for authentication session lifecycle operations.
/// </summary>
public sealed class AuthenticationSessionOptions
{
    /// <summary>
    /// Default session lifetime. Defaults to 14 days and must be positive.
    /// </summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Maximum session lifetime accepted from callers. Defaults to 30 days and must be at least <see cref="DefaultLifetime"/>.
    /// </summary>
    public TimeSpan MaximumLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Minimum elapsed time before updating <see cref="AuthenticationSession.LastSeenAt"/>.
    /// Defaults to 5 minutes and cannot be negative.
    /// </summary>
    public TimeSpan LastSeenUpdateThreshold { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Number of random bytes used to generate raw session tokens. Defaults to 32 and must be between 32 and 192.
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
    /// Maximum accepted IP address length. Defaults to 45 characters and must be positive.
    /// </summary>
    public int MaxIpAddressLength { get; set; } = 45;

    /// <summary>
    /// Maximum accepted user agent length. Defaults to 512 characters and must be positive.
    /// </summary>
    public int MaxUserAgentLength { get; set; } = 512;

    /// <summary>
    /// Maximum accepted metadata length. Defaults to 8192 characters and must be positive.
    /// </summary>
    public int MaxMetadataLength { get; set; } = 8192;

    /// <summary>Determines whether the supplied options are valid.</summary>
    /// <param name="options">Options instance to validate.</param>
    /// <returns><see langword="true" /> when the options are valid; otherwise <see langword="false" />.</returns>
    public static bool Validate(AuthenticationSessionOptions? options) =>
        options is not null
        && options.DefaultLifetime > TimeSpan.Zero
        && options.MaximumLifetime >= options.DefaultLifetime
        && options.LastSeenUpdateThreshold >= TimeSpan.Zero
        && options.TokenByteLength is >= 32 and <= 192
        && options.MaxIpAddressLength > 0
        && options.MaxUserAgentLength > 0
        && options.MaxMetadataLength > 0;
}
