using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Tenants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Links validated OpenID Connect identities to an existing Ashlar user.
/// </summary>
/// <remarks>
/// Applications should treat calls to this service as sensitive account security operations and require
/// appropriate recent verification, such as fresh MFA, before invoking it.
/// </remarks>
public sealed class AshlarExternalAccountLinkService
{
    private readonly ICredentialService _credentialService;
    private readonly IIdentityRepository _repository;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;

    /// <summary>
    /// Initializes a new instance of the external account link service.
    /// </summary>
    /// <param name="credentialService">The Ashlar credential service.</param>
    /// <param name="repository">The Ashlar identity repository.</param>
    /// <param name="options">The OAuth options monitor.</param>
    public AshlarExternalAccountLinkService(
        ICredentialService credentialService,
        IIdentityRepository repository,
        IOptionsMonitor<AshlarOAuthOptions> options)
    {
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Completes account linking using the ASP.NET Core temporary external authentication ticket.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="tenant">The tenant scope, when the application is tenant-aware.</param>
    /// <param name="credentialMetadata">Optional non-secret credential metadata to store with the link. Do not pass access tokens, refresh tokens, ID tokens, authorization codes, cookies, or raw claim payloads.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external account link result.</returns>
    public async Task<AshlarExternalAccountLinkResult> CompleteOidcLinkAsync(
        HttpContext httpContext,
        Guid currentUserId,
        string providerName,
        TenantContext? tenant = null,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var provider = GetOidcProvider(providerName);
        if (provider == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        var result = await httpContext.AuthenticateAsync(_options.CurrentValue.ExternalSignInScheme);
        if (!result.Succeeded)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        await httpContext.SignOutAsync(_options.CurrentValue.ExternalSignInScheme);

        if (!MatchesProvider(result, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkOidcAccountAsync(currentUserId, providerName, result, tenant, credentialMetadata, cancellationToken);
    }

    /// <summary>
    /// Links a completed ASP.NET Core external authentication ticket to the current Ashlar user.
    /// </summary>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="authenticateResult">The completed external authentication result.</param>
    /// <param name="tenant">The tenant scope, when the application is tenant-aware.</param>
    /// <param name="credentialMetadata">Optional non-secret credential metadata to store with the link. Do not pass access tokens, refresh tokens, ID tokens, authorization codes, cookies, or raw claim payloads.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external account link result.</returns>
    public async Task<AshlarExternalAccountLinkResult> LinkOidcAccountAsync(
        Guid currentUserId,
        string providerName,
        AuthenticateResult authenticateResult,
        TenantContext? tenant = null,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticateResult);

        var provider = GetOidcProvider(providerName);
        if (provider == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        if (!authenticateResult.Succeeded)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        if (!MatchesProvider(authenticateResult, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkOidcAccountAsync(currentUserId, providerName, authenticateResult.Principal, tenant, credentialMetadata, cancellationToken);
    }

    /// <summary>
    /// Links an already validated OpenID Connect principal to the current Ashlar user.
    /// </summary>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal.</param>
    /// <param name="tenant">The tenant scope, when the application is tenant-aware.</param>
    /// <param name="credentialMetadata">Optional non-secret credential metadata to store with the link. Do not pass access tokens, refresh tokens, ID tokens, authorization codes, cookies, or raw claim payloads.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external account link result.</returns>
    public async Task<AshlarExternalAccountLinkResult> LinkOidcAccountAsync(
        Guid currentUserId,
        string providerName,
        System.Security.Claims.ClaimsPrincipal principal,
        TenantContext? tenant = null,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (currentUserId == Guid.Empty)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.InvalidPrincipal);
        }

        var providerOptions = GetOidcProvider(providerName);
        if (providerOptions == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = OidcExternalIdentityAssertionMapper.Map(providerOptions.ProviderName, principal);
        }
        catch (InvalidOperationException)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.InvalidPrincipal);
        }
        catch (ArgumentException)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.InvalidPrincipal);
        }

        if (!await CurrentUserMatchesTenantAsync(currentUserId, tenant, cancellationToken))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Failed, assertion);
        }

        var provider = new OidcAuthenticationProvider(providerOptions.ProviderName);
        var linkResult = await _credentialService.LinkCredentialAsync(
            currentUserId,
            assertion,
            provider,
            credentialValue: null,
            credentialMetadata: credentialMetadata,
            cancellationToken: cancellationToken);

        if (linkResult.Succeeded)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Linked, assertion, linkResult);
        }

        var status = linkResult.FailureCode?.Value switch
        {
            AshlarFailureCodes.AlreadyLinkedToSelfValue => AshlarExternalAccountLinkStatus.AlreadyLinked,
            AshlarFailureCodes.AlreadyLinkedToOtherValue => AshlarExternalAccountLinkStatus.AlreadyLinkedToAnotherUser,
            AshlarFailureCodes.InvalidProviderKeyValue => AshlarExternalAccountLinkStatus.InvalidPrincipal,
            _ => AshlarExternalAccountLinkStatus.Failed
        };

        return new AshlarExternalAccountLinkResult(status, assertion, linkResult);
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

    private async Task<bool> CurrentUserMatchesTenantAsync(Guid currentUserId, TenantContext? tenant, CancellationToken cancellationToken)
    {
        if (tenant == null)
        {
            return true;
        }

        var user = await _repository.GetUserByIdAsync(currentUserId, cancellationToken);
        return user switch
        {
            null => false,
            ITenantUser tenantUser => tenantUser.TenantId == tenant.TenantId,
            _ => tenant.TenantId == null
        };
    }

    private static bool MatchesProvider(AuthenticateResult result, AshlarOidcProviderOptions provider)
    {
        return result.Properties is { } properties
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.ProviderName, out var providerName)
            && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.SchemeName, out var schemeName)
            && string.Equals(provider.ProviderName, providerName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(provider.SchemeName, schemeName, StringComparison.Ordinal);
    }
}
