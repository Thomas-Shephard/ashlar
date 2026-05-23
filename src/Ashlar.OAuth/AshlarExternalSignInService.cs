using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Completes ASP.NET Core external sign-in callbacks by delegating to Ashlar authentication.
/// </summary>
public sealed class AshlarExternalSignInService
{
    private readonly IAuthenticationPipeline _authenticationPipeline;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;

    /// <summary>
    /// Initializes a new instance of the external sign-in service.
    /// </summary>
    /// <param name="authenticationPipeline">The Ashlar authentication pipeline.</param>
    /// <param name="options">The OAuth options monitor.</param>
    public AshlarExternalSignInService(
        IAuthenticationPipeline authenticationPipeline,
        IOptionsMonitor<AshlarOAuthOptions> options)
    {
        _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Completes sign-in using the ASP.NET Core authentication result for the configured provider scheme.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="tenantId">The tenant for tenant-aware lookup, when applicable.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external sign-in result.</returns>
    public async Task<AshlarExternalSignInResult> CompleteOidcSignInAsync(
        HttpContext httpContext,
        string providerName,
        Guid? tenantId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var assertionResult = await CompleteOidcAssertionAsync(httpContext, providerName, cancellationToken);
        if (!assertionResult.Succeeded)
        {
            return new AshlarExternalSignInResult(MapAssertionStatus(assertionResult.Status), Assertion: assertionResult.Assertion);
        }

        var assertion = assertionResult.Assertion!;
        var response = await _authenticationPipeline.LoginAsync(CreateAuthenticationContext(httpContext, tenantId), assertion, cancellationToken);
        return new AshlarExternalSignInResult(MapStatus(response), response, assertion);
    }

    /// <summary>
    /// Completes sign-in callback handling only up to a mapped Ashlar external identity assertion.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external assertion completion result.</returns>
    /// <remarks>
    /// Use this method when the host application must pass the mapped assertion through its own authentication
    /// orchestration before issuing a session, such as when MFA policy is applied by <c>IAuthenticationOrchestrator</c>.
    /// </remarks>
    public async Task<AshlarExternalAssertionResult> CompleteOidcAssertionAsync(
        HttpContext httpContext,
        string providerName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var provider = GetOidcProvider(providerName);
        if (provider == null)
        {
            await AshlarExternalTicket.TryClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme);
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.UnsupportedProvider);
        }

        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme);

        if (!result.Succeeded || result.Principal == null)
        {
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.AuthenticationFailed);
        }

        if (!MatchesProvider(result, provider))
        {
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.ProviderMismatch);
        }

        try
        {
            var assertion = OidcExternalIdentityAssertionMapper.Map(provider.ProviderName, result.Principal, provider.ProviderKeyMode);
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.Succeeded, assertion);
        }
        catch (InvalidOperationException)
        {
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.InvalidPrincipal);
        }
        catch (ArgumentException)
        {
            return new AshlarExternalAssertionResult(AshlarExternalAssertionStatus.InvalidPrincipal);
        }
    }

    /// <summary>
    /// Completes sign-in from an already validated external principal.
    /// </summary>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal. Do not pass principals built from request data or unvalidated tokens.</param>
    /// <param name="context">The Ashlar authentication context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external sign-in result.</returns>
    public async Task<AshlarExternalSignInResult> CompleteOidcSignInAsync(
        string providerName,
        System.Security.Claims.ClaimsPrincipal principal,
        AuthenticationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);

        var provider = GetOidcProvider(providerName);
        if (provider == null)
        {
            return new AshlarExternalSignInResult(AshlarExternalSignInStatus.UnsupportedProvider);
        }

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = OidcExternalIdentityAssertionMapper.Map(provider.ProviderName, principal, provider.ProviderKeyMode);
        }
        catch (InvalidOperationException)
        {
            return new AshlarExternalSignInResult(AshlarExternalSignInStatus.InvalidPrincipal);
        }
        catch (ArgumentException)
        {
            return new AshlarExternalSignInResult(AshlarExternalSignInStatus.InvalidPrincipal);
        }

        var response = await _authenticationPipeline.LoginAsync(context, assertion, cancellationToken);
        return new AshlarExternalSignInResult(MapStatus(response), response, assertion);
    }

    private AshlarOidcProviderOptions? GetOidcProvider(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
        {
            return null;
        }

        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        return _options.CurrentValue.OidcProviders.TryGetValue(normalizedProviderName, out var provider) ? provider : null;
    }

    private static AuthenticationContext CreateAuthenticationContext(HttpContext httpContext, Guid? tenantId)
    {
        return new AuthenticationContext(
            TenantId: tenantId,
            IpAddress: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString(),
            CorrelationId: httpContext.TraceIdentifier);
    }

    private static bool MatchesProvider(AuthenticateResult result, AshlarOidcProviderOptions provider)
    {
        return result.Properties is { } properties
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.ProviderName, out var providerName)
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.SchemeName, out var schemeName)
            && string.Equals(provider.ProviderName, providerName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(provider.SchemeName, schemeName, StringComparison.Ordinal);
    }

    private static AshlarExternalSignInStatus MapStatus(AuthenticationResponse response)
    {
        if (response.Succeeded)
        {
            return AshlarExternalSignInStatus.Succeeded;
        }

        return response.Status switch
        {
            AuthenticationStatus.Disabled => AshlarExternalSignInStatus.Disabled,
            AuthenticationStatus.MfaRequired => AshlarExternalSignInStatus.MfaRequired,
            _ => AshlarExternalSignInStatus.AshlarAuthenticationFailed
        };
    }

    private static AshlarExternalSignInStatus MapAssertionStatus(AshlarExternalAssertionStatus status)
    {
        return status switch
        {
            AshlarExternalAssertionStatus.AuthenticationFailed => AshlarExternalSignInStatus.AuthenticationFailed,
            AshlarExternalAssertionStatus.UnsupportedProvider => AshlarExternalSignInStatus.UnsupportedProvider,
            AshlarExternalAssertionStatus.InvalidPrincipal => AshlarExternalSignInStatus.InvalidPrincipal,
            AshlarExternalAssertionStatus.ProviderMismatch => AshlarExternalSignInStatus.ProviderMismatch,
            _ => AshlarExternalSignInStatus.Unknown
        };
    }
}
