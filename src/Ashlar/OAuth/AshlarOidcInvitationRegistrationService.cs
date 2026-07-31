using Ashlar.Auditing;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Accepts Ashlar invitations only after validating a configured OpenID Connect identity, then links that identity to the accepted user.
/// </summary>
public sealed class AshlarOidcInvitationRegistrationService
{
    private readonly IInvitationService _invitationService;
    private readonly IValidatedExternalCredentialLinkService _credentialLinkService;
    private readonly AshlarDurableTransactionProvider _transactionProvider;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _oauthOptions;
    private readonly IOidcInvitationEmailMatchPolicy _emailMatchPolicy;

    /// <summary>
    /// Initializes a new instance of the OIDC invitation registration service.
    /// </summary>
    /// <param name="invitationService">The invitation service.</param>
    /// <param name="credentialLinkService">Core credential-link mutation service.</param>
    /// <param name="transactionProvider">Durable transaction provider used for invitation acceptance.</param>
    /// <param name="oauthOptions">The OAuth options monitor.</param>
    /// <param name="emailMatchPolicy">The invitation email match policy.</param>
    internal AshlarOidcInvitationRegistrationService(
        IInvitationService invitationService,
        IValidatedExternalCredentialLinkService credentialLinkService,
        AshlarDurableTransactionProvider transactionProvider,
        IOptionsMonitor<AshlarOAuthOptions> oauthOptions,
        IOidcInvitationEmailMatchPolicy emailMatchPolicy)
    {
        _invitationService = invitationService ?? throw new ArgumentNullException(nameof(invitationService));
        _credentialLinkService = credentialLinkService ?? throw new ArgumentNullException(nameof(credentialLinkService));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _oauthOptions = oauthOptions ?? throw new ArgumentNullException(nameof(oauthOptions));
        _emailMatchPolicy = emailMatchPolicy ?? throw new ArgumentNullException(nameof(emailMatchPolicy));
    }

    /// <summary>
    /// Completes invitation registration using the ASP.NET Core temporary external authentication ticket.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="invitationToken">The invitation token.</param>
    /// <param name="providerName">The configured Ashlar OIDC provider name.</param>
    /// <param name="displayName">Optional user display name for invitation acceptance.</param>
    /// <param name="context">Optional Ashlar authentication context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The invitation registration result, including ticket, provider, invitation, and credential-link failures.</returns>
    /// <remarks>
    /// The ASP.NET Core OpenID Connect handler must have already validated the remote provider response and written
    /// the temporary external ticket. This method verifies that the ticket belongs to the configured Ashlar OIDC
    /// provider, clears it, enforces invitation email-match policy, and links the configured OIDC provider key to the accepted
    /// user.
    /// </remarks>
    public async Task<AshlarOidcInvitationRegistrationResult> CompleteOidcInvitationRegistrationAsync(
        HttpContext httpContext,
        string? invitationToken,
        string providerName,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        return await CompleteOidcInvitationRegistrationCoreAsync(
            httpContext,
            providerName,
            new OidcInvitationRegistrationState(invitationToken, displayName),
            context,
            cancellationToken);
    }

    /// <summary>
    /// Completes invitation registration using invitation state stored in the ASP.NET Core temporary external authentication ticket.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="providerName">The configured Ashlar OIDC provider name.</param>
    /// <param name="invitationTokenPropertyName">Authentication property name containing the Ashlar invitation token.</param>
    /// <param name="displayNamePropertyName">Optional authentication property name containing the requested display name.</param>
    /// <param name="context">Optional Ashlar authentication context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The invitation registration result, including ticket, provider, invitation, and credential-link failures.</returns>
    /// <remarks>
    /// Use this overload when callback state must not appear in the OAuth redirect URI. The ASP.NET Core OpenID
    /// Connect handler must preserve the supplied authentication properties in the temporary external ticket.
    /// Ashlar reads and clears that ticket before accepting the invitation or linking the OIDC credential.
    /// </remarks>
    public async Task<AshlarOidcInvitationRegistrationResult> CompleteOidcInvitationRegistrationFromPropertiesAsync(
        HttpContext httpContext,
        string providerName,
        string invitationTokenPropertyName,
        string? displayNamePropertyName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(invitationTokenPropertyName);

        return await CompleteOidcInvitationRegistrationCoreAsync(
            httpContext,
            providerName,
            new OidcInvitationRegistrationState(null, null, invitationTokenPropertyName, displayNamePropertyName),
            context,
            cancellationToken);
    }

    private async Task<AshlarOidcInvitationRegistrationResult> CompleteOidcInvitationRegistrationCoreAsync(
        HttpContext httpContext,
        string providerName,
        OidcInvitationRegistrationState invitationState,
        AuthenticationContext? context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        var provider = AshlarExternalProviderResolver.GetProvider(_oauthOptions.CurrentValue, providerName);
        if (provider == null || provider.Type != ProviderType.Oidc)
        {
            await AshlarExternalTicket.TryClearAsync(httpContext, _oauthOptions.CurrentValue.ExternalSignInScheme, CancellationToken.None);
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider);
        }

        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _oauthOptions.CurrentValue.ExternalSignInScheme, cancellationToken);

        if (!result.Succeeded || result.Principal == null)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.AuthenticationFailed);
        }

        var (matched, properties) = AshlarExternalProviderResolver.MatchProvider(result, provider);
        if (!matched || properties is null)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.ProviderMismatch);
        }

        var invitationToken = invitationState.InvitationToken;
        var displayName = invitationState.DisplayName;
        if (invitationState.InvitationTokenPropertyName != null)
        {
            properties.Items.TryGetValue(invitationState.InvitationTokenPropertyName, out invitationToken);
            if (invitationState.DisplayNamePropertyName != null)
            {
                properties.Items.TryGetValue(invitationState.DisplayNamePropertyName, out displayName);
            }
        }

        if (invitationToken == null)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.InvalidInvitation);
        }

        return await RegisterValidatedOidcInvitationAsync(
            invitationToken,
            provider,
            result.Principal,
            displayName,
            context,
            cancellationToken);
    }

    private sealed record OidcInvitationRegistrationState(
        string? InvitationToken,
        string? DisplayName,
        string? InvitationTokenPropertyName = null,
        string? DisplayNamePropertyName = null);

    private async Task<AshlarOidcInvitationRegistrationResult> RegisterValidatedOidcInvitationAsync(
        string? invitationToken,
        AshlarExternalProvider provider,
        System.Security.Claims.ClaimsPrincipal principal,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (!AshlarExternalProviderResolver.TryMapAssertion(provider, principal, out var assertion))
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal);
        }

        var preview = await _invitationService.GetInvitationAcceptancePreviewAsync(invitationToken, context, cancellationToken);
        if (!preview.TryGetValue(out var invitation))
        {
            return new AshlarOidcInvitationRegistrationResult(MapInvitationPreviewFailure(preview));
        }

        if (context?.TenantId is Guid requestedTenantId && invitation.TenantId != requestedTenantId)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.InvalidInvitation);
        }

        var emailMatch = _emailMatchPolicy.Validate(new OidcInvitationEmailMatchContext(provider.ProviderName, principal, invitation));
        if (!emailMatch.Succeeded)
        {
            return new AshlarOidcInvitationRegistrationResult(emailMatch.Status ?? AshlarOidcInvitationRegistrationStatus.Failed);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var acceptance = await _invitationService.AcceptInvitationAsync(
            new AcceptInvitationRequest { Token = invitationToken, UserName = displayName },
            context,
            cancellationToken);
        if (!acceptance.TryGetValue(out var accepted))
        {
            await transaction.CommitAsync(cancellationToken);
            return new AshlarOidcInvitationRegistrationResult(MapInvitationFailure(acceptance), InvitationAcceptance: acceptance);
        }

        if (accepted.UserId == Guid.Empty)
        {
            await transaction.CommitAsync(cancellationToken);
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.Failed, InvitationAcceptance: acceptance);
        }

        var link = await _credentialLinkService.LinkValidatedExternalCredentialAsync(new InternalValidatedExternalCredentialLinkRequest(
            accepted.UserId,
            assertion.ProviderIdentity.Type,
            assertion.ProviderIdentity.Name,
            assertion.ProviderKey,
            new AuditContext(context?.UserId, context?.IpAddress, context?.UserAgent, context?.CorrelationId),
            invitation.TenantId), cancellationToken);

        if (!link.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new AshlarOidcInvitationRegistrationResult(MapLinkFailure(link), accepted.UserId, acceptance, link);
        }

        await transaction.CommitAsync(cancellationToken);
        return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.Registered, accepted.UserId, acceptance, link);
    }

    private static AshlarOidcInvitationRegistrationStatus MapInvitationFailure(Result<InvitationAcceptanceResult> result)
    {
        return result.GetFailure().Code.Value switch
        {
            AshlarFailureCodes.InvalidInvitationValue => AshlarOidcInvitationRegistrationStatus.InvalidInvitation,
            AshlarFailureCodes.RateLimitedValue => AshlarOidcInvitationRegistrationStatus.RateLimited,
            _ => AshlarOidcInvitationRegistrationStatus.Failed
        };
    }

    private static AshlarOidcInvitationRegistrationStatus MapInvitationPreviewFailure(Result<InvitationAcceptancePreview> result)
    {
        return result.GetFailure().Code.Value switch
        {
            AshlarFailureCodes.RateLimitedValue => AshlarOidcInvitationRegistrationStatus.RateLimited,
            AshlarFailureCodes.InvalidInvitationValue => AshlarOidcInvitationRegistrationStatus.InvalidInvitation,
            _ => AshlarOidcInvitationRegistrationStatus.Failed
        };
    }

    private static AshlarOidcInvitationRegistrationStatus MapLinkFailure(Result result)
    {
        return result.GetFailure().Code.Value switch
        {
            AshlarFailureCodes.AlreadyLinkedToSelfValue => AshlarOidcInvitationRegistrationStatus.AlreadyLinked,
            AshlarFailureCodes.AlreadyLinkedToOtherValue => AshlarOidcInvitationRegistrationStatus.AlreadyLinkedToAnotherUser,
            _ => AshlarOidcInvitationRegistrationStatus.LinkFailed
        };
    }
}
