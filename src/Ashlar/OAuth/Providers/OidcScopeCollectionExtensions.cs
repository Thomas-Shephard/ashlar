using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Ashlar.OAuth.Providers;

internal static class OidcScopeCollectionExtensions
{
    public static void AddIfMissing(this OpenIdConnectOptions options, string scope)
    {
        if (!options.Scope.Contains(scope, StringComparer.Ordinal))
        {
            options.Scope.Add(scope);
        }
    }
}
