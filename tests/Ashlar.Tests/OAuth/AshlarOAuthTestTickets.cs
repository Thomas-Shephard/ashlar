using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Tests.OAuth;

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

    public static Task<AshlarOidcInvitationRegistrationResult> RegisterOidcInvitationAsync(
        this AshlarOidcInvitationRegistrationService service,
        string? invitationToken,
        string providerName,
        AuthenticateResult authenticateResult,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticateResult);

        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService>(new TicketAuthenticationService(authenticateResult));
        var httpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        return service.CompleteOidcInvitationRegistrationAsync(
            httpContext, invitationToken, providerName, displayName, context, cancellationToken);
    }

    private sealed class TicketAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(result);

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }
}
