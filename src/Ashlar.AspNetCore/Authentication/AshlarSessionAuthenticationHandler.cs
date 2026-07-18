using System.Security.Claims;
using System.Globalization;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ashlar.AspNetCore.Authentication;

/// <summary>
/// Provides ashlar session authentication handler behavior.
/// </summary>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
/// <param name="encoder">The encoder value.</param>
/// <param name="sessionService">The session service value.</param>
public sealed class AshlarSessionAuthenticationHandler(
    IOptionsMonitor<AshlarSessionAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IAuthenticationSessionService sessionService)
    : AuthenticationHandler<AshlarSessionAuthenticationOptions>(options, logger, encoder)
{
    private readonly IAuthenticationSessionService _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));

    /// <summary>
    /// Performs the handle authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <returns>The operation result.</returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(Options.CookieName, out var token) || string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        var validation = await _sessionService.ValidateSessionAsync(token, Context.RequestAborted);
        if (validation.ValidatedSession == null)
        {
            Response.Cookies.Delete(Options.CookieName, Options.Cookie.Build(Context));
            return AuthenticateResult.Fail("Ashlar session validation failed.");
        }

        var session = validation.ValidatedSession;
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, session.UserId.ToString("D"), ClaimValueTypes.String, Options.ClaimsIssuer),
            new Claim(AshlarClaimTypes.SessionId, session.Id.ToString("D"), ClaimValueTypes.String, Options.ClaimsIssuer),
            new Claim(ClaimTypes.AuthenticationMethod, Scheme.Name, ClaimValueTypes.String, Options.ClaimsIssuer)
        };
        if (session.TenantId.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.TenantId, session.TenantId.Value.ToString("D"), ClaimValueTypes.String, Options.ClaimsIssuer));
        }

        AddSessionAuthenticationClaims(claims, session);
        Context.Items[AshlarHttpContextItems.ValidatedAuthenticationSession] = session;

        var identity = new ClaimsIdentity(claims, Scheme.Name, ClaimTypes.NameIdentifier, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    /// <summary>
    /// Performs the handle challenge <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="properties">The properties value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the handle forbidden <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="properties">The properties value.</param>
    /// <returns>The operation result.</returns>
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

    private static void AddSessionAuthenticationClaims(List<Claim> claims, ValidatedAuthenticationSession session)
    {
        if (session.AuthenticatedAt.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.AuthenticatedAt, session.AuthenticatedAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
        }

        if (session.PrimaryProvider.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderType, session.PrimaryProvider.Value.StorageTypeValue));
            claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderName, session.PrimaryProvider.Value.Name));
        }

        if (session.AdditionalVerificationAt.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationAt, session.AdditionalVerificationAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
        }

        if (session.AdditionalVerificationProvider.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderType, session.AdditionalVerificationProvider.Value.StorageTypeValue));
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderName, session.AdditionalVerificationProvider.Value.Name));
        }

        if (!string.IsNullOrWhiteSpace(session.AdditionalVerificationFactor))
        {
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationFactor, session.AdditionalVerificationFactor));
        }
    }
}
