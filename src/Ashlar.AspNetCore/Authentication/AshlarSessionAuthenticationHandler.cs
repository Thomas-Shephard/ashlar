using System.Security.Claims;
using System.Text.Encodings.Web;
using Ashlar.Identity.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Authentication;

public sealed class AshlarSessionAuthenticationHandler(
    IOptionsMonitor<AshlarSessionAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IAuthenticationSessionService sessionService)
    : AuthenticationHandler<AshlarSessionAuthenticationOptions>(options, logger, encoder)
{
    private readonly IAuthenticationSessionService _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(Options.CookieName, out var token) || string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        var validation = await _sessionService.ValidateSessionAsync(token, Context.RequestAborted);
        if (!validation.Succeeded || validation.Session == null || validation.UserId == null)
        {
            Response.Cookies.Delete(Options.CookieName, Options.Cookie.Build(Context));
            return AuthenticateResult.Fail("Ashlar session validation failed.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, validation.UserId.Value.ToString("D"), ClaimValueTypes.String, Options.ClaimsIssuer),
            new Claim(AshlarClaimTypes.SessionId, validation.Session.Id.ToString("D"), ClaimValueTypes.String, Options.ClaimsIssuer),
            new Claim(ClaimTypes.AuthenticationMethod, Scheme.Name, ClaimValueTypes.String, Options.ClaimsIssuer)
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name, ClaimTypes.NameIdentifier, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (!Options.LoginPath.HasValue)
        {
            return base.HandleChallengeAsync(properties);
        }

        if (IsApiRequest())
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        Response.Redirect(BuildRedirectUriWithReturnUrl(Options.LoginPath, properties.RedirectUri));
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        if (!Options.AccessDeniedPath.HasValue)
        {
            return base.HandleForbiddenAsync(properties);
        }

        if (IsApiRequest())
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        Response.Redirect(BuildRedirectUriWithReturnUrl(Options.AccessDeniedPath, properties.RedirectUri));
        return Task.CompletedTask;
    }

    private string BuildRedirectUriWithReturnUrl(string path, string? returnUrl)
    {
        var redirectUri = string.IsNullOrEmpty(returnUrl)
            ? path
            : QueryHelpers.AddQueryString(path, "ReturnUrl", returnUrl);

        return BuildRedirectUri(redirectUri);
    }

    private bool IsApiRequest()
    {
        return string.Equals(Request.Headers.XRequestedWith, "XMLHttpRequest", StringComparison.OrdinalIgnoreCase)
            || Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }
}
