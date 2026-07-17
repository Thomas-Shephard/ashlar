using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Tenants;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
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
    private const string UnlinkPurpose = "external-account-unlinking";

    private readonly IExternalAccountCredentialLinker _credentialLinker;
    private readonly IAccountSecurityAdministrationService _accountSecurityAdministration;
    private readonly IUserRepository _repository;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISecurityEventSink _securityEvents;

    internal AshlarExternalAccountLinkService(
        IExternalAccountCredentialLinker credentialLinker,
        IAccountSecurityAdministrationService accountSecurityAdministration,
        IUserRepository repository,
        IOptionsMonitor<AshlarOAuthOptions> options,
        TimeProvider timeProvider,
        ISecurityEventSink? securityEventSink = null)
    {
        _credentialLinker = credentialLinker ?? throw new ArgumentNullException(nameof(credentialLinker));
        _accountSecurityAdministration = accountSecurityAdministration ?? throw new ArgumentNullException(nameof(accountSecurityAdministration));
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _securityEvents = securityEventSink ?? new NullSecurityEventSink();
    }

    /// <summary>
    /// Creates Ashlar-owned authentication properties for an external-provider challenge whose resulting ticket may be used for account linking.
    /// </summary>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="currentSessionId">The current Ashlar authentication session id.</param>
    /// <param name="redirectUri">The URI to return to after the external provider callback.</param>
    /// <returns>Properties bound to account-linking purpose, user, and session.</returns>
    public static AuthenticationProperties CreateExternalLinkChallengeProperties(Guid currentUserId, Guid currentSessionId, string? redirectUri = null)
    {
        if (currentUserId == Guid.Empty) throw new ArgumentException("The current user id cannot be empty.", nameof(currentUserId));
        if (currentSessionId == Guid.Empty) throw new ArgumentException("The current session id cannot be empty.", nameof(currentSessionId));

        var properties = new AuthenticationProperties { RedirectUri = redirectUri };
        properties.Items[AshlarOAuthAuthenticationProperties.Purpose] = LinkPurpose;
        properties.Items[AshlarOAuthAuthenticationProperties.LinkingUserId] = currentUserId.ToString("D");
        properties.Items[AshlarOAuthAuthenticationProperties.LinkingSessionId] = currentSessionId.ToString("D");
        return properties;
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

        if (!IsLinkingTicket(result.Properties, currentUserId, currentSessionId!.Value))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.AuthenticationFailed);
        }

        if (!AshlarExternalProviderResolver.MatchesProvider(result, provider))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.ProviderMismatch);
        }

        return await LinkValidatedExternalAccountCoreAsync(
            new ExternalAccountLinkCoreRequest(
                currentUserId,
                new AshlarValidatedExternalPrincipal(provider, result.Principal),
                tenant,
                freshMfaProof,
                currentSessionId,
                new AuditContext(
                    currentUserId,
                    httpContext.Connection.RemoteIpAddress?.ToString(),
                    httpContext.Request.Headers.UserAgent.ToString(),
                    httpContext.TraceIdentifier),
                CredentialMetadata: null),
            cancellationToken: cancellationToken);
    }

    private static bool IsLinkingTicket(AuthenticationProperties? properties, Guid userId, Guid sessionId) =>
        properties?.Items.TryGetValue(AshlarOAuthAuthenticationProperties.Purpose, out var purpose) == true
        && string.Equals(purpose, LinkPurpose, StringComparison.Ordinal)
        && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.LinkingUserId, out var boundUserId)
        && Guid.TryParse(boundUserId, out var parsedUserId)
        && parsedUserId == userId
        && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.LinkingSessionId, out var boundSessionId)
        && Guid.TryParse(boundSessionId, out var parsedSessionId)
        && parsedSessionId == sessionId;

    private AshlarFailureCode? ValidateFreshLinkProof(
        Guid currentUserId,
        FreshMfaVerificationProof? freshMfaProof,
        Guid? currentSessionId,
        TenantContext tenant)
    {
        return FreshVerificationProofValidator.ValidateMfaProof(currentUserId, tenant, freshMfaProof, currentSessionId, _timeProvider.GetUtcNow(), LinkPurpose);
    }

    private async Task<AshlarExternalAccountLinkResult> LinkValidatedExternalAccountCoreAsync(
        ExternalAccountLinkCoreRequest request,
        CancellationToken cancellationToken = default)
    {
        var (currentUserId, principal, tenant, freshMfaProof, currentSessionId, audit, credentialMetadata) = request;
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
        var linkResult = await _credentialLinker.LinkExternalAccountCredentialAsync(
            new ExternalAccountCredentialLinkRequest(
                currentUserId,
                assertion,
                provider,
                freshMfaProof,
                currentSessionId,
                tenant,
                audit,
                CredentialMetadata: credentialMetadata),
            cancellationToken);

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
    /// <param name="freshMfaProof">Ashlar-issued fresh MFA proof minted for <c>external-account-unlinking</c>.</param>
    /// <param name="currentSessionId">Current Ashlar session id from the authenticated request. It must match <paramref name="freshMfaProof" />.</param>
    /// <param name="request">The account-security audit metadata and explicit tenant scope for the operation. All-tenant scope is not a self-service unlink boundary.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The external account unlink result.</returns>
    /// <remarks>
    /// Account unlinking mutates future sign-in methods. The service requires an Ashlar-issued fresh MFA proof for
    /// the target user, tenant, current session, and <c>external-account-unlinking</c> purpose before it checks or
    /// revokes credentials. User interfaces should prefer generic failure messages even though the result
    /// status is explicit for application branching. Unlinking revokes active credentials for the configured
    /// external provider family, such as all active Google credentials stored under the configured Google
    /// provider name, rather than a single provider key or raw external account key.
    /// </remarks>
    public async Task<AshlarExternalAccountUnlinkResult> UnlinkExternalAccountAsync(
        Guid currentUserId,
        string providerName,
        FreshMfaVerificationProof? freshMfaProof,
        Guid? currentSessionId,
        AshlarExternalAccountUnlinkRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (currentUserId == Guid.Empty)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.Failed);
        }

        if (!request.Audit.ActorUserId.Equals(currentUserId))
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.Failed);
        }

        var providerOptions = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (providerOptions == null)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.UnsupportedProvider);
        }
        var provider = new AuthenticationProviderKey(providerOptions.Type, providerOptions.ProviderName);

        if (FreshVerificationProofValidator.ValidateMfaProof(currentUserId, request.Tenant, freshMfaProof, currentSessionId, _timeProvider.GetUtcNow(), UnlinkPurpose) is { } proofFailure)
        {
            await _securityEvents.RecordAsync(new AshlarSecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = AshlarSecurityEventTypes.UserCredentialsRevoked,
                OccurredAt = _timeProvider.GetUtcNow(),
                Outcome = SecurityEventOutcomes.Failure,
                UserId = currentUserId,
                TenantId = request.Tenant.TenantId,
                ActorUserId = request.Audit.ActorUserId,
                Provider = provider,
                IpAddress = request.Audit.IpAddress,
                UserAgent = request.Audit.UserAgent,
                CorrelationId = request.Audit.CorrelationId,
                FailureReason = proofFailure.Value
            }, cancellationToken);
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.Failed);
        }

        var actor = new AccountSecurityActorContext(currentUserId, request.Tenant, currentSessionId!.Value, freshMfaProof!, request.Audit);
        var revokeResult = await _accountSecurityAdministration.RevokeCredentialsAsync(new RevokeAccountCredentialsRequest(
            currentUserId, provider, actor, request.Tenant, reason: request.Reason, preservePrimarySignInMethod: true), cancellationToken);
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

    private static AshlarExternalAccountUnlinkStatus MapRevokeFailure(Result<AccountSecurityOperationResult> result)
    {
        return result.FailureCode?.Value switch
        {
            AshlarFailureCodes.UserNotFoundValue => AshlarExternalAccountUnlinkStatus.UserNotFound,
            AshlarFailureCodes.TenantMismatchValue => AshlarExternalAccountUnlinkStatus.TenantMismatch,
            AshlarFailureCodes.LastPrimarySignInMethodValue => AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod,
            _ => AshlarExternalAccountUnlinkStatus.Failed
        };
    }

    private sealed record ExternalAccountLinkCoreRequest(
        Guid CurrentUserId,
        AshlarValidatedExternalPrincipal Principal,
        TenantContext Tenant,
        FreshMfaVerificationProof? FreshMfaProof,
        Guid? CurrentSessionId,
        AuditContext? Audit,
        string? CredentialMetadata);
}
