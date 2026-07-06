using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Tenants;
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
    private const string LinkPurpose = "external-account-linking";

    private readonly ICredentialService _credentialService;
    private readonly IAccountSecurityService _accountSecurityService;
    private readonly IUserRepository _repository;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;

    /// <summary>
    /// Initializes a new instance of the external account link service.
    /// </summary>
    /// <param name="credentialService">The Ashlar credential service.</param>
    /// <param name="accountSecurityService">The Ashlar account security service.</param>
    /// <param name="repository">The repository used to load the current Ashlar user.</param>
    /// <param name="options">The OAuth options monitor.</param>
    public AshlarExternalAccountLinkService(
        ICredentialService credentialService,
        IAccountSecurityService accountSecurityService,
        IUserRepository repository,
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
    /// <param name="freshMfaProof">Ashlar-issued fresh MFA proof minted for <c>external-account-linking</c>.</param>
    /// <param name="currentSessionId">Current Ashlar session id from the authenticated request. It must match <paramref name="freshMfaProof" />.</param>
    /// <param name="tenant">The tenant scope. Use <see cref="TenantContext.Global" /> for global users.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The account-link result, including provider mismatch or invalid-principal statuses when the temporary ticket cannot be trusted for the configured provider.</returns>
    /// <remarks>
    /// Account linking mutates future sign-in methods. The caller must pass an Ashlar-issued fresh MFA proof for
    /// the target user, tenant, current session, and <c>external-account-linking</c> purpose. The ASP.NET Core
    /// external authentication middleware must have already validated the remote provider response and written the
    /// temporary external ticket. This method verifies that ticket against the configured Ashlar provider, clears it,
    /// and then links the stable external provider key to the current user.
    /// </remarks>
    public async Task<AshlarExternalAccountLinkResult> CompleteExternalLinkAsync(
        HttpContext httpContext,
        Guid currentUserId,
        string providerName,
        FreshMfaVerificationProof? freshMfaProof,
        Guid? currentSessionId,
        TenantContext tenant,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(tenant);

        var proofFailure = ValidateFreshLinkProof(currentUserId, freshMfaProof, currentSessionId, tenant);
        if (proofFailure != null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Failed);
        }

        var provider = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (provider == null)
        {
            await AshlarExternalTicket.TryClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme, CancellationToken.None);
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _options.CurrentValue.ExternalSignInScheme, cancellationToken);

        if (!result.Succeeded || result.Principal == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(result, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkValidatedExternalAccountCoreAsync(currentUserId, new AshlarValidatedExternalPrincipal(provider, result.Principal), tenant, cancellationToken: cancellationToken);
    }

    internal async Task<AshlarExternalAccountLinkResult> LinkExternalAccountAsync(
        Guid currentUserId,
        string providerName,
        AshlarExternalAccountLinkRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.AuthenticateResult);
        ArgumentNullException.ThrowIfNull(request.Tenant);

        var proofFailure = ValidateFreshLinkProof(currentUserId, request.FreshMfaProof, request.CurrentSessionId, request.Tenant);
        if (proofFailure != null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Failed);
        }

        var provider = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (provider == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.UnsupportedProvider);
        }

        if (!request.AuthenticateResult.Succeeded || request.AuthenticateResult.Principal == null)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(request.AuthenticateResult, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkValidatedExternalAccountCoreAsync(
            currentUserId,
            new AshlarValidatedExternalPrincipal(provider, request.AuthenticateResult.Principal),
            request.Tenant,
            request.CredentialMetadata,
            cancellationToken);
    }

    private static AshlarFailureCode? ValidateFreshLinkProof(
        Guid currentUserId,
        FreshMfaVerificationProof? freshMfaProof,
        Guid? currentSessionId,
        TenantContext tenant)
    {
        return FreshVerificationProofValidator.ValidateMfaProof(currentUserId, tenant, freshMfaProof, currentSessionId, TimeProvider.System.GetUtcNow(), LinkPurpose);
    }

    private async Task<AshlarExternalAccountLinkResult> LinkValidatedExternalAccountCoreAsync(
        Guid currentUserId,
        AshlarValidatedExternalPrincipal principal,
        TenantContext tenant,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = AshlarExternalProviderResolver.MapAssertion(principal.Provider, principal.Principal);
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

        var provider = AshlarExternalProviderResolver.CreateAuthenticationProvider(principal.Provider);
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
    /// provider name, rather than a single provider key or raw external account key.
    /// </remarks>
    public async Task<AshlarExternalAccountUnlinkResult> UnlinkExternalAccountAsync(
        Guid currentUserId,
        string providerName,
        AccountSecurityOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.ThrowIfInvalidScope();

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

        if (!request.IncludeAllTenants)
        {
            ArgumentNullException.ThrowIfNull(request.Tenant);
            var tenant = request.Tenant;
            if (!IsInRequestedTenant(user, tenant))
            {
                return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.TenantMismatch);
            }
        }

        var provider = new AuthenticationProviderKey(providerOptions.Type, providerOptions.ProviderName);
        var postureResult = await _accountSecurityService.GetUserSecurityPostureAsync(
            currentUserId,
            new AccountSecurityPostureRequest(GetPostureTenant(user, request)),
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

    private async Task<bool> CurrentUserMatchesTenantAsync(Guid currentUserId, TenantContext tenant, CancellationToken cancellationToken)
    {
        var user = await _repository.GetUserByIdAsync(currentUserId, cancellationToken);
        return user != null && IsInRequestedTenant(user, tenant);
    }

    private static bool IsInRequestedTenant(IUser user, TenantContext tenant)
    {
        return user switch
        {
            ITenantUser tenantUser => tenantUser.TenantId == tenant.TenantId,
            _ => tenant.TenantId == null
        };
    }

    private static TenantContext? GetPostureTenant(IUser user, AccountSecurityOperationRequest request)
    {
        if (!request.IncludeAllTenants)
        {
            return request.Tenant;
        }

        return user is ITenantUser tenantUser
            ? new TenantContext(tenantUser.TenantId)
            : TenantContext.Global;
    }

    private static bool HasUsablePrimarySignInMethodAfterUnlink(AccountSecurityPosture posture, AuthenticationProviderKey provider)
    {
        return posture.PrimaryCredentials.Any(item =>
            item.IsAvailable
            && item.IsPrimaryCredential
            && item.Provider != provider);
    }

    private static AshlarExternalAccountUnlinkStatus MapPostureFailure(Result<AccountSecurityPosture> result)
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
