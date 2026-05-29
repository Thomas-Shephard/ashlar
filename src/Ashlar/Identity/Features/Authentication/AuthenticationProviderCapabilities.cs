namespace Ashlar.Identity.Features.Authentication;

/// <summary>
/// Centralizes authentication provider capability classification.
/// </summary>
internal static class AuthenticationProviderCapabilities
{
    public static bool IsPrimary(IAuthenticationProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return provider is IPrimaryAuthenticationProvider;
    }

    public static bool IsSecondaryFactor(IAuthenticationProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        return provider is ISecondaryAuthenticationFactorProvider;
    }
}
