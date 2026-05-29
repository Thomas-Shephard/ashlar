using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Models;

namespace Ashlar.Passkeys;

/// <summary>
/// Configures Ashlar passkey ceremonies.
/// </summary>
public sealed class PasskeyOptions
{
    /// <summary>
    /// Gets or sets the authentication provider key used for stored credentials.
    /// </summary>
    public AuthenticationProviderKey ProviderKey { get; set; } = AuthenticationProviderKey.Passkey;
    /// <summary>
    /// Gets or sets the WebAuthn relying party id. This must be a host name matching the origin host or one of its parent domains.
    /// </summary>
    public string RelyingPartyId { get; set; } = "localhost";
    /// <summary>
    /// Gets or sets the WebAuthn relying party display name.
    /// </summary>
    public string RelyingPartyName { get; set; } = "Ashlar";
    /// <summary>
    /// Gets or sets the expected browser origin. This must be an origin only, without user info, path, query, or fragment.
    /// </summary>
    public string Origin { get; set; } = "https://localhost";
    /// <summary>
    /// Gets or sets the passkey challenge lifetime.
    /// </summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>
    /// Gets or sets the number of random bytes in new challenges.
    /// </summary>
    public int ChallengeBytes { get; set; } = 32;
    /// <summary>
    /// Gets or sets the WebAuthn user verification requirement.
    /// </summary>
    public string UserVerification { get; set; } = "preferred";
    /// <summary>
    /// Gets or sets the WebAuthn attestation conveyance preference.
    /// </summary>
    public string Attestation { get; set; } = "none";
    /// <summary>
    /// Gets or sets whether resident/discoverable credentials are required.
    /// </summary>
    public bool RequireResidentKey { get; set; } = true;
    /// <summary>
    /// Gets or sets the source-based rate limit for starting passkey authentication challenges.
    /// </summary>
    public RateLimitRule AuthenticationChallengeStartRateLimit { get; set; } = new() { PermitLimit = 30, Window = TimeSpan.FromMinutes(15) };

    /// <summary>
    /// Validates the configured passkey options.
    /// </summary>
    /// <param name="options">The options value.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(PasskeyOptions options)
    {
        return options.ProviderKey.Type != default
            && !string.IsNullOrWhiteSpace(options.ProviderKey.Name)
            && !string.IsNullOrWhiteSpace(options.RelyingPartyName)
            && Uri.TryCreate(options.Origin, UriKind.Absolute, out var origin)
            && IsOriginOnly(origin)
            && IsValidRelyingPartyId(options.RelyingPartyId, origin.Host)
            && (origin.Scheme == Uri.UriSchemeHttps || IsLocalDevelopmentOrigin(origin))
            && options.ChallengeLifetime > TimeSpan.Zero
            && options.ChallengeLifetime.TotalMilliseconds <= uint.MaxValue
            && options.ChallengeBytes >= 16
            && AuthenticationRateLimitRuleValidator.IsValid(options.AuthenticationChallengeStartRateLimit)
            && IsUserVerificationValid(options.UserVerification)
            && IsAttestationValid(options.Attestation);
    }

    private static bool IsUserVerificationValid(string? value)
    {
        return IsOneOf(value, "required", "preferred", "discouraged");
    }

    private static bool IsAttestationValid(string? value)
    {
        return IsOneOf(value, "none", "direct", "enterprise", "indirect");
    }

    private static bool IsOneOf(string? value, params string[] allowed)
    {
        return !string.IsNullOrWhiteSpace(value)
            && allowed.Any(v => string.Equals(v, value.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLocalDevelopmentOrigin(Uri origin)
    {
        return origin.Scheme == Uri.UriSchemeHttp
            && (origin.IsLoopback || string.Equals(origin.Host, "localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsOriginOnly(Uri origin)
    {
        return string.IsNullOrEmpty(origin.UserInfo)
            && string.IsNullOrEmpty(origin.Query)
            && string.IsNullOrEmpty(origin.Fragment)
            && origin.AbsolutePath == "/";
    }

    private static bool IsValidRelyingPartyId(string? relyingPartyId, string originHost)
    {
        // WebAuthn RP IDs are domain names, not URLs, paths, or host:port values.
        if (string.IsNullOrWhiteSpace(relyingPartyId)
            || relyingPartyId.Contains('/', StringComparison.Ordinal)
            || relyingPartyId.Contains(':', StringComparison.Ordinal))
        {
            return false;
        }

        var rpId = relyingPartyId.Trim().TrimEnd('.');
        var host = originHost.Trim().TrimEnd('.');
        return string.Equals(host, rpId, StringComparison.OrdinalIgnoreCase)
            || host.EndsWith($".{rpId}", StringComparison.OrdinalIgnoreCase);
    }
}
