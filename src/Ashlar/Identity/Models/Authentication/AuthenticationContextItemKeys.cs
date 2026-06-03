namespace Ashlar.Identity.Models.Authentication;

/// <summary>
/// Defines provider-neutral keys for values carried through <see cref="AuthenticationContext.Items" />.
/// </summary>
public static class AuthenticationContextItemKeys
{
    /// <summary>
    /// The raw remembered MFA device token supplied by the transport layer.
    /// </summary>
    public const string RememberedMfaDeviceToken = "ashlar.remembered_mfa_device_token";
}

/// <summary>
/// Provides helpers for strongly named authentication context item access.
/// </summary>
public static class AuthenticationContextItemExtensions
{
    /// <summary>
    /// Returns a copy of the context with the remembered MFA device token item set.
    /// </summary>
    /// <param name="context">The authentication context.</param>
    /// <param name="token">The raw remembered MFA device token.</param>
    /// <returns>The updated context.</returns>
    public static AuthenticationContext WithRememberedMfaDeviceToken(this AuthenticationContext context, string token)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var items = context.Items == null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(context.Items, StringComparer.Ordinal);
        items[AuthenticationContextItemKeys.RememberedMfaDeviceToken] = token;
        return context with { Items = items };
    }

    /// <summary>
    /// Gets a non-empty remembered MFA device token from the context when one is present.
    /// </summary>
    /// <param name="context">The authentication context.</param>
    /// <param name="token">The remembered MFA device token.</param>
    /// <returns><see langword="true" /> when a token was present.</returns>
    public static bool TryGetRememberedMfaDeviceToken(this AuthenticationContext context, out string token)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Items?.TryGetValue(AuthenticationContextItemKeys.RememberedMfaDeviceToken, out var value) == true
            && !string.IsNullOrWhiteSpace(value))
        {
            token = value;
            return true;
        }

        token = string.Empty;
        return false;
    }
}
