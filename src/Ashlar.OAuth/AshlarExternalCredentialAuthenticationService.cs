using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Maps ASP.NET Core external OIDC callbacks to Ashlar assertions and can authenticate those credentials with Ashlar.
/// </summary>
public sealed class AshlarExternalCredentialAuthenticationService
{
    private readonly IAuthenticationPipeline _authenticationPipeline;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;

    /// <summary>
    /// Initializes a new instance of the external credential authentication service.
    /// </summary>
    /// <param name="authenticationPipeline">The Ashlar authentication pipeline.</param>
    /// <param name="options">The OAuth options monitor.</param>
    public AshlarExternalCredentialAuthenticationService(
        IAuthenticationPipeline authenticationPipeline,
        IOptionsMonitor<AshlarOAuthOptions> options)
    {
        _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Validates the external OIDC callback, maps it to an Ashlar assertion, and authenticates that credential with Ashlar.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="tenantId">The tenant for tenant-aware lookup, when applicable.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external credential authentication result.</returns>
    /// <remarks>
    /// This method does not issue an application session or cookie. Applications with MFA or other orchestration policy
    /// should prefer <see cref="CompleteOidcAssertionAsync(HttpContext, string)"/>, pass the returned assertion through
    /// <see cref="IAuthenticationOrchestrator"/>, and issue a session only after orchestration succeeds.
    /// </remarks>
    public async Task<AshlarExternalCredentialAuthenticationResult> CompleteOidcCredentialAuthenticationAsync(
        HttpContext httpContext,
        string providerName,
        Guid? tenantId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var assertionResult = await CompleteOidcAssertionAsync(httpContext, providerName);
        if (!assertionResult.Succeeded)
        {
            return new AshlarExternalCredentialAuthenticationResult(MapAssertionStatus(assertionResult.Status), Assertion: assertionResult.Assertion);
        }

        var assertion = assertionResult.Assertion!;
        var response = await _authenticationPipeline.LoginAsync(CreateAuthenticationContext(httpContext, tenantId), assertion, cancellationToken);
        return new AshlarExternalCredentialAuthenticationResult(MapStatus(response), response, assertion);
    }

    /// <summary>
    /// Maps an already validated external principal to an Ashlar assertion and authenticates that credential with Ashlar.
    /// </summary>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal. Do not pass principals built from request data or unvalidated tokens.</param>
    /// <param name="context">The Ashlar authentication context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external credential authentication result.</returns>
    /// <remarks>
    /// This method does not issue an application session or cookie. It is safe for session issuance only when the host
    /// application's policy allows the authenticated external credential response to be treated as complete. Applications
    /// with MFA policy must not issue sessions directly from this result; use <see cref="CompleteOidcAssertionAsync(HttpContext, string)"/>
    /// and the host orchestration pipeline instead.
    /// </remarks>
    public async Task<AshlarExternalCredentialAuthenticationResult> CompleteOidcCredentialAuthenticationAsync(
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
            return new AshlarExternalCredentialAuthenticationResult(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider);
        }

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = OidcExternalIdentityAssertionMapper.Map(provider.ProviderName, principal, provider.ProviderKeyMode);
        }
        catch (InvalidOperationException)
        {
            return new AshlarExternalCredentialAuthenticationResult(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal);
        }
        catch (ArgumentException)
        {
            return new AshlarExternalCredentialAuthenticationResult(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal);
        }

        var response = await _authenticationPipeline.LoginAsync(context, assertion, cancellationToken);
        return new AshlarExternalCredentialAuthenticationResult(MapStatus(response), response, assertion);
    }

    /// <summary>
    /// Completes callback handling only up to a mapped Ashlar external identity assertion.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <returns>The external assertion completion result.</returns>
    /// <remarks>
    /// Use this method when the host application must pass the mapped assertion through its own authentication
    /// orchestration before issuing a session, such as when MFA policy is applied by <see cref="IAuthenticationOrchestrator"/>.
    /// A successful result means the external OIDC credential was validated and mapped; it does not mean an application
    /// session may be issued.
    /// </remarks>
    public async Task<AshlarExternalAssertionResult> CompleteOidcAssertionAsync(
        HttpContext httpContext,
        string providerName)
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

    private static AshlarExternalCredentialAuthenticationStatus MapStatus(AuthenticationResponse response)
    {
        if (response.Succeeded)
        {
            return AshlarExternalCredentialAuthenticationStatus.Succeeded;
        }

        return response.Status switch
        {
            AuthenticationStatus.Disabled => AshlarExternalCredentialAuthenticationStatus.Disabled,
            AuthenticationStatus.MfaRequired => AshlarExternalCredentialAuthenticationStatus.MfaRequired,
            _ => AshlarExternalCredentialAuthenticationStatus.AshlarAuthenticationFailed
        };
    }

    private static AshlarExternalCredentialAuthenticationStatus MapAssertionStatus(AshlarExternalAssertionStatus status)
    {
        return status switch
        {
            AshlarExternalAssertionStatus.AuthenticationFailed => AshlarExternalCredentialAuthenticationStatus.AuthenticationFailed,
            AshlarExternalAssertionStatus.UnsupportedProvider => AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider,
            AshlarExternalAssertionStatus.InvalidPrincipal => AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal,
            AshlarExternalAssertionStatus.ProviderMismatch => AshlarExternalCredentialAuthenticationStatus.ProviderMismatch,
            // Assertion success only means the external OIDC credential was validated and mapped; MFA or other policy may still block session issuance.
            AshlarExternalAssertionStatus.Succeeded => AshlarExternalCredentialAuthenticationStatus.Unknown,
            _ => AshlarExternalCredentialAuthenticationStatus.Unknown
        };
    }
}
