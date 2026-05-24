using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Tenants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Links validated external identities to an existing Ashlar user.
/// </summary>
/// <remarks>
/// Applications should treat calls to this service as sensitive account security operations and require
/// appropriate recent verification, such as fresh MFA, before invoking it.
/// </remarks>
public sealed class AshlarExternalAccountLinkService
{
    private readonly ICredentialService _credentialService;
    private readonly IAccountSecurityService _accountSecurityService;
    private readonly IIdentityRepository _repository;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;

    /// <summary>
    /// Initializes a new instance of the external account link service.
    /// </summary>
    /// <param name="credentialService">The Ashlar credential service.</param>
    /// <param name="accountSecurityService">The Ashlar account security service.</param>
    /// <param name="repository">The Ashlar identity repository.</param>
    /// <param name="options">The OAuth options monitor.</param>
    public AshlarExternalAccountLinkService(
        ICredentialService credentialService,
        IAccountSecurityService accountSecurityService,
        IIdentityRepository repository,
        IOptionsMonitor<AshlarOAuthOptions> options)
    {
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _accountSecurityService = accountSecurityService ?? throw new ArgumentNullException(nameof(accountSecurityService));
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
    public async Task<AshlarExternalAccountLinkResult> CompleteExternalLinkAsync(
        HttpContext httpContext,
        Guid currentUserId,
        string providerName,
        TenantContext? tenant = null,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var provider = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (provider == null)
        {
            await AshlarExternalTicket.TryClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme);
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme);

        if (!result.Succeeded || result.Principal == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(result, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkExternalAccountAsync(currentUserId, providerName, result, tenant, credentialMetadata, cancellationToken);
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
    public async Task<AshlarExternalAccountLinkResult> LinkExternalAccountAsync(
        Guid currentUserId,
        string providerName,
        AuthenticateResult authenticateResult,
        TenantContext? tenant = null,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticateResult);

        var provider = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (provider == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        if (!authenticateResult.Succeeded || authenticateResult.Principal == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(authenticateResult, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkExternalAccountAsync(currentUserId, providerName, authenticateResult.Principal, tenant, credentialMetadata, cancellationToken);
    }

    /// <summary>
    /// Links an already validated external principal to the current Ashlar user.
    /// </summary>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="principal">The validated external principal. Do not pass principals built from request data or unvalidated tokens.</param>
    /// <param name="tenant">The tenant scope, when the application is tenant-aware.</param>
    /// <param name="credentialMetadata">Optional non-secret credential metadata to store with the link. Do not pass access tokens, refresh tokens, ID tokens, authorization codes, cookies, or raw claim payloads.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external account link result.</returns>
    public async Task<AshlarExternalAccountLinkResult> LinkExternalAccountAsync(
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

        var providerOptions = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (providerOptions == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = AshlarExternalProviderResolver.MapAssertion(providerOptions, principal);
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

        var provider = AshlarExternalProviderResolver.CreateAuthenticationProvider(providerOptions);
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

    /// <summary>
    /// Unlinks a configured external provider from the current Ashlar user by revoking that provider's credential family.
    /// </summary>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="providerName">The configured Ashlar provider name.</param>
    /// <param name="request">The account-security audit metadata for the operation.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external account unlink result.</returns>
    /// <remarks>
    /// Applications should treat calls to this service as sensitive account security operations and require
    /// appropriate recent verification, such as fresh MFA, before invoking it. The service does not require or
    /// enforce fresh MFA itself. User interfaces should prefer generic failure messages even though the result
    /// status is explicit for application branching. Unlinking revokes active credentials for the configured
    /// external provider family, such as all active Google credentials stored under the configured Google
    /// provider name, rather than a single provider subject or raw external account key.
    /// </remarks>
    public async Task<AshlarExternalAccountUnlinkResult> UnlinkExternalAccountAsync(
        Guid currentUserId,
        string providerName,
        AccountSecurityOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (currentUserId == Guid.Empty)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.UserNotFound);
        }

        var providerOptions = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (providerOptions == null)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.UnsupportedProvider);
        }

        var user = await _repository.GetUserByIdAsync(currentUserId, cancellationToken);
        if (user == null)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.UserNotFound);
        }

        if (!IsInRequestedTenant(user, request.Tenant))
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.TenantMismatch);
        }

        var provider = new AuthenticationProviderKey(providerOptions.Type, providerOptions.ProviderName);
        var postureResult = await _accountSecurityService.GetUserSecurityPostureAsync(
            currentUserId,
            new UserSecurityPostureRequest(request.Tenant),
            cancellationToken);
        if (!postureResult.Succeeded || postureResult.Value == null)
        {
            return new AshlarExternalAccountUnlinkResult(MapPostureFailure(postureResult));
        }

        var linkedCredentialCount = postureResult.Value.CredentialInventory.Count(item =>
            item.Provider == provider && item.IsAvailable);
        if (linkedCredentialCount == 0)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.NotLinked);
        }

        if (!HasUsablePrimarySignInMethodAfterUnlink(postureResult.Value, provider))
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod);
        }

        var revokeResult = await _accountSecurityService.RevokeCredentialsAsync(currentUserId, provider, request, cancellationToken);
        if (!revokeResult.Succeeded)
        {
            return new AshlarExternalAccountUnlinkResult(MapRevokeFailure(revokeResult), revokeResult);
        }

        return new AshlarExternalAccountUnlinkResult(
            revokeResult.Value?.CredentialsRevoked > 0
                ? AshlarExternalAccountUnlinkStatus.Unlinked
                : AshlarExternalAccountUnlinkStatus.NotLinked,
            revokeResult);
    }

    private async Task<bool> CurrentUserMatchesTenantAsync(Guid currentUserId, TenantContext? tenant, CancellationToken cancellationToken)
    {
        if (tenant == null)
        {
            return true;
        }

        var user = await _repository.GetUserByIdAsync(currentUserId, cancellationToken);
        return user != null && IsInRequestedTenant(user, tenant);
    }

    private static bool IsInRequestedTenant(IUser user, TenantContext? tenant)
    {
        if (tenant == null)
        {
            return true;
        }

        return user switch
        {
            ITenantUser tenantUser => tenantUser.TenantId == tenant.TenantId,
            _ => tenant.TenantId == null
        };
    }

    private static bool HasUsablePrimarySignInMethodAfterUnlink(UserSecurityPosture posture, AuthenticationProviderKey provider)
    {
        return posture.PrimaryCredentials.Any(item =>
            item.IsAvailable
            && item.IsPrimaryCredential
            && item.Provider != provider);
    }

    private static AshlarExternalAccountUnlinkStatus MapPostureFailure(Result<UserSecurityPosture> result)
    {
        return result.FailureCode?.Value == AshlarFailureCodes.UserNotFoundValue
            ? AshlarExternalAccountUnlinkStatus.UserNotFound
            : AshlarExternalAccountUnlinkStatus.Failed;
    }

    private static AshlarExternalAccountUnlinkStatus MapRevokeFailure(Result<AccountSecurityOperationResult> result)
    {
        return result.FailureCode?.Value == AshlarFailureCodes.UserNotFoundValue
            ? AshlarExternalAccountUnlinkStatus.UserNotFound
            : AshlarExternalAccountUnlinkStatus.Failed;
    }

}
