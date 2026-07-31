using Ashlar.Auditing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Links validated external identities to an existing Ashlar user.
/// </summary>
/// <remarks>
/// Linking accepts only an Ashlar-validated external ticket and an Ashlar-issued fresh authentication proof
/// bound to the target user, tenant, session, and linking purpose.
/// </remarks>
public sealed class AshlarExternalAccountLinkService
{
    /// <summary>Purpose required when minting proofs for external-account linking.</summary>
    public const string LinkingProofPurpose = "external-account-linking";

    /// <summary>Purpose required when minting proofs for external-account unlinking.</summary>
    public const string UnlinkingProofPurpose = "external-account-unlinking";

    private readonly IValidatedExternalCredentialLinkService _credentialLinkService;
    private readonly ActiveSessionFreshProofValidator _proofValidator;
    private readonly IAccountSecurityMutationExecutor _accountSecurityMutationExecutor;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ISecurityEventSink _securityEvents;

    internal AshlarExternalAccountLinkService(
        IValidatedExternalCredentialLinkService credentialLinkService,
        ActiveSessionFreshProofValidator proofValidator,
        IAccountSecurityMutationExecutor accountSecurityMutationExecutor,
        IOptionsMonitor<AshlarOAuthOptions> options,
        TimeProvider timeProvider,
        ISecurityEventSink? securityEventSink = null)
    {
        _credentialLinkService = credentialLinkService ?? throw new ArgumentNullException(nameof(credentialLinkService));
        _proofValidator = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));
        _accountSecurityMutationExecutor = accountSecurityMutationExecutor ?? throw new ArgumentNullException(nameof(accountSecurityMutationExecutor));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _securityEvents = securityEventSink ?? new NullSecurityEventSink();
    }

    /// <summary>
    /// Creates Ashlar-owned authentication properties for an external-provider challenge whose resulting ticket may be used for account linking.
    /// </summary>
    /// <param name="currentUserId">The currently authenticated Ashlar user id.</param>
    /// <param name="currentSessionId">The current Ashlar authentication session id.</param>
    /// <param name="returnPath">An optional root-relative local application path to return to after the external provider callback. Absolute and scheme-relative URIs are not allowed.</param>
    /// <returns>Properties bound to account-linking purpose, user, and session.</returns>
    public static AuthenticationProperties CreateExternalLinkChallengeProperties(Guid currentUserId, Guid currentSessionId, string? returnPath = null)
    {
        if (currentUserId == Guid.Empty) throw new ArgumentException("The current user id cannot be empty.", nameof(currentUserId));
        if (currentSessionId == Guid.Empty) throw new ArgumentException("The current session id cannot be empty.", nameof(currentSessionId));
        if (returnPath is not null && !IsLocalReturnPath(returnPath))
            throw new ArgumentException("The return path must be a root-relative local application path.", nameof(returnPath));

        var properties = new AuthenticationProperties { RedirectUri = returnPath };
        properties.Items[AshlarOAuthAuthenticationProperties.Purpose] = LinkingProofPurpose;
        properties.Items[AshlarOAuthAuthenticationProperties.LinkingUserId] = currentUserId.ToString("D");
        properties.Items[AshlarOAuthAuthenticationProperties.LinkingSessionId] = currentSessionId.ToString("D");
        return properties;
    }

    private static bool IsLocalReturnPath(string path)
    {
        while (path.Length > 0
               && path[0] == '/'
               && (path.Length == 1 || path[1] is not ('/' or '\\'))
               && !path.Any(char.IsWhiteSpace)
               && !path.Any(char.IsControl)
               && Uri.IsWellFormedUriString($"http://localhost{path}", UriKind.Absolute))
        {
            var decoded = Uri.UnescapeDataString(path);
            if (decoded == path) return true;
            path = decoded;
        }

        return false;
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

        if (await _proofValidator.ValidateAsync(
                currentUserId, tenant, freshMfaProof, currentSessionId, LinkingProofPurpose, cancellationToken) is { } proofFailure)
        {
            return new AshlarExternalAccountLinkResult(
                AshlarExternalAccountLinkStatus.Failed,
                CredentialLink: Result.Failure(proofFailure));
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
            currentUserId,
            provider,
            result.Principal,
            tenant,
            new AuditContext(
                currentUserId,
                httpContext.Connection.RemoteIpAddress?.ToString(),
                httpContext.Request.Headers.UserAgent.ToString(),
                httpContext.TraceIdentifier),
            cancellationToken);
    }

    private static bool IsLinkingTicket(AuthenticationProperties? properties, Guid userId, Guid sessionId) =>
        properties?.Items.TryGetValue(AshlarOAuthAuthenticationProperties.Purpose, out var purpose) == true
        && string.Equals(purpose, LinkingProofPurpose, StringComparison.Ordinal)
        && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.LinkingUserId, out var boundUserId)
        && Guid.TryParse(boundUserId, out var parsedUserId)
        && parsedUserId == userId
        && properties.Items.TryGetValue(AshlarOAuthAuthenticationProperties.LinkingSessionId, out var boundSessionId)
        && Guid.TryParse(boundSessionId, out var parsedSessionId)
        && parsedSessionId == sessionId;

    private async Task<AshlarExternalAccountLinkResult> LinkValidatedExternalAccountCoreAsync(
        Guid currentUserId,
        AshlarExternalProvider provider,
        System.Security.Claims.ClaimsPrincipal principal,
        TenantContext tenant,
        AuditContext audit,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (!AshlarExternalProviderResolver.TryMapAssertion(provider, principal, out var assertion))
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.InvalidPrincipal);
        }

        var linkResult = await _credentialLinkService.LinkValidatedExternalCredentialAsync(
            new InternalValidatedExternalCredentialLinkRequest(
                currentUserId,
                assertion.ProviderIdentity.Type,
                assertion.ProviderIdentity.Name,
                assertion.ProviderKey,
                audit,
                tenant.TenantId), cancellationToken);

        if (linkResult.Succeeded)
        {
            return new AshlarExternalAccountLinkResult(AshlarExternalAccountLinkStatus.Linked, linkResult);
        }

        var status = linkResult.GetFailure().Code.Value switch
        {
            AshlarFailureCodes.AlreadyLinkedToSelfValue => AshlarExternalAccountLinkStatus.AlreadyLinked,
            AshlarFailureCodes.AlreadyLinkedToOtherValue => AshlarExternalAccountLinkStatus.AlreadyLinkedToAnotherUser,
            AshlarFailureCodes.InvalidProviderKeyValue => AshlarExternalAccountLinkStatus.InvalidPrincipal,
            _ => AshlarExternalAccountLinkStatus.Failed
        };

        return new AshlarExternalAccountLinkResult(status, linkResult);
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

        if (!request.Audit.ActorUserId.Equals(currentUserId))
        {
            await RecordUnlinkFailureAsync(currentUserId, request, AshlarFailureCodes.ValidationErrorValue);
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.Failed);
        }

        if (await _proofValidator.ValidateAsync(
                currentUserId, request.Tenant, freshMfaProof, currentSessionId, UnlinkingProofPurpose, cancellationToken) is { } proofFailure)
        {
            await RecordUnlinkFailureAsync(currentUserId, request, proofFailure.Value);
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.Failed);
        }

        var providerOptions = AshlarExternalProviderResolver.GetProvider(_options.CurrentValue, providerName);
        if (providerOptions == null)
        {
            return new AshlarExternalAccountUnlinkResult(AshlarExternalAccountUnlinkStatus.UnsupportedProvider);
        }
        var provider = new AuthenticationProviderKey(providerOptions.Type, providerOptions.ProviderName);

        var revokeResult = await _accountSecurityMutationExecutor.RevokeCredentialsAsync(
            currentUserId,
            provider,
            new AccountSecurityOperationRequest(request.Audit, request.Tenant, request.Reason, PreservePrimarySignInMethod: true),
            cancellationToken);
        if (!revokeResult.TryGetValue(out var revoke))
        {
            return new AshlarExternalAccountUnlinkResult(MapRevokeFailure(revokeResult), revokeResult);
        }

        return new AshlarExternalAccountUnlinkResult(
            revoke.CredentialsRevoked > 0
                ? AshlarExternalAccountUnlinkStatus.Unlinked
                : AshlarExternalAccountUnlinkStatus.NotLinked,
            revokeResult);
    }

    private Task RecordUnlinkFailureAsync(Guid userId, AshlarExternalAccountUnlinkRequest request, string failureReason) =>
        _securityEvents.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = AshlarSecurityEventTypes.UserCredentialsRevoked,
            OccurredAt = _timeProvider.GetUtcNow(),
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = request.Tenant.TenantId,
            ActorUserId = userId,
            IpAddress = request.Audit.IpAddress,
            UserAgent = request.Audit.UserAgent,
            CorrelationId = request.Audit.CorrelationId,
            FailureReason = failureReason
        }, CancellationToken.None);

    private static AshlarExternalAccountUnlinkStatus MapRevokeFailure(Result<AccountSecurityOperationResult> result)
    {
        return result.GetFailure().Code.Value switch
        {
            AshlarFailureCodes.UserNotFoundValue => AshlarExternalAccountUnlinkStatus.UserNotFound,
            AshlarFailureCodes.TenantMismatchValue => AshlarExternalAccountUnlinkStatus.TenantMismatch,
            AshlarFailureCodes.LastPrimarySignInMethodValue => AshlarExternalAccountUnlinkStatus.WouldRemoveLastSignInMethod,
            _ => AshlarExternalAccountUnlinkStatus.Failed
        };
    }
}
