using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Ashlar.OAuth.Tests;

internal static class AshlarOAuthTestTickets
{
    public static AuthenticateResult CreateExternalTicket(
        string providerName,
        string schemeName,
        ProviderType providerType,
        ClaimsPrincipal principal)
    {
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = providerName;
        properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = schemeName;
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderType] = providerType.Value;

        return AuthenticateResult.Success(new AuthenticationTicket(principal, properties, "Ashlar.OAuth.External"));
    }
}
