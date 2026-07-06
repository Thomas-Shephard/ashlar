using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Models.Invitations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Ashlar.OAuth;

/// <summary>
/// Accepts Ashlar invitations only after validating a configured OpenID Connect identity, then links that identity to the accepted user.
/// </summary>
public sealed class AshlarOidcInvitationRegistrationService
{
    private readonly IInvitationService _invitationService;
    private readonly ICredentialService _credentialService;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _oauthOptions;
    private readonly IOidcInvitationEmailMatchPolicy _emailMatchPolicy;

    /// <summary>
    /// Initializes a new instance of the OIDC invitation registration service.
    /// </summary>
    /// <param name="invitationService">The invitation service.</param>
    /// <param name="credentialService">The credential service.</param>
    /// <param name="transactionProvider">The transaction provider.</param>
    /// <param name="oauthOptions">The OAuth options monitor.</param>
    /// <param name="emailMatchPolicy">The invitation email match policy.</param>
    public AshlarOidcInvitationRegistrationService(
        IInvitationService invitationService,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        IOptionsMonitor<AshlarOAuthOptions> oauthOptions,
        IOidcInvitationEmailMatchPolicy emailMatchPolicy)
    {
        _invitationService = invitationService ?? throw new ArgumentNullException(nameof(invitationService));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
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

        var provider = GetOidcProvider(providerName);
        if (provider == null)
        {
            await AshlarExternalTicket.TryClearAsync(httpContext, _oauthOptions.CurrentValue.ExternalSignInScheme, CancellationToken.None);
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider);
        }

        var result = await AshlarExternalTicket.AuthenticateAndClearAsync(httpContext, _oauthOptions.CurrentValue.ExternalSignInScheme, cancellationToken);

        if (!result.Succeeded || result.Principal == null)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.AuthenticationFailed);
        }

        var externalProvider = CreateExternalProvider(provider);
        if (!AshlarExternalProviderResolver.MatchesProvider(result, externalProvider))
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.ProviderMismatch);
        }

        var invitationToken = invitationState.InvitationToken;
        var displayName = invitationState.DisplayName;
        if (invitationState.InvitationTokenPropertyName != null)
        {
            result.Properties?.Items.TryGetValue(invitationState.InvitationTokenPropertyName, out invitationToken);
            if (invitationState.DisplayNamePropertyName != null)
            {
                result.Properties?.Items.TryGetValue(invitationState.DisplayNamePropertyName, out displayName);
            }
        }

        return await RegisterValidatedOidcInvitationAsync(
            invitationToken,
            new AshlarValidatedExternalPrincipal(externalProvider, result.Principal),
            displayName,
            context,
            cancellationToken);
    }

    private sealed record OidcInvitationRegistrationState(
        string? InvitationToken,
        string? DisplayName,
        string? InvitationTokenPropertyName = null,
        string? DisplayNamePropertyName = null);

    internal Task<AshlarOidcInvitationRegistrationResult> RegisterOidcInvitationAsync(
        string? invitationToken,
        string providerName,
        AuthenticateResult authenticateResult,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticateResult);

        var provider = GetOidcProvider(providerName);
        if (provider == null)
        {
            return Task.FromResult(new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider));
        }

        if (!authenticateResult.Succeeded || authenticateResult.Principal == null)
        {
            return Task.FromResult(new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.AuthenticationFailed));
        }

        var externalProvider = CreateExternalProvider(provider);
        if (!AshlarExternalProviderResolver.MatchesProvider(authenticateResult, externalProvider))
        {
            return Task.FromResult(new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
        }

        return RegisterValidatedOidcInvitationAsync(
            invitationToken,
            new AshlarValidatedExternalPrincipal(externalProvider, authenticateResult.Principal),
            displayName,
            context,
            cancellationToken);
    }

    private async Task<AshlarOidcInvitationRegistrationResult> RegisterValidatedOidcInvitationAsync(
        string? invitationToken,
        AshlarValidatedExternalPrincipal principal,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = OidcExternalIdentityAssertionMapper.Map(
                principal.Provider.ProviderName,
                principal.Principal,
                principal.Provider.OidcProviderKeyMode);
        }
        catch (InvalidOperationException)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal);
        }
        catch (ArgumentException)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.InvalidPrincipal);
        }

        var preview = await _invitationService.GetInvitationAcceptancePreviewAsync(invitationToken, context, cancellationToken);
        if (!preview.Succeeded || preview.Value == null)
        {
            return new AshlarOidcInvitationRegistrationResult(MapInvitationPreviewFailure(preview), Assertion: assertion);
        }

        if (context?.TenantId is Guid requestedTenantId && preview.Value.TenantId != requestedTenantId)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.InvalidInvitation, Assertion: assertion);
        }

        var emailMatch = _emailMatchPolicy.Validate(new OidcInvitationEmailMatchContext(principal.Provider.ProviderName, principal.Principal, preview.Value));
        if (!emailMatch.Succeeded)
        {
            return new AshlarOidcInvitationRegistrationResult(emailMatch.Status ?? AshlarOidcInvitationRegistrationStatus.Failed, Assertion: assertion);
        }

        if (_transactionProvider is not IAshlarDurableTransactionProvider)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.Failed, Assertion: assertion);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var acceptance = await _invitationService.AcceptInvitationAsync(
            new AcceptInvitationRequest { Token = invitationToken, UserName = displayName },
            context,
            cancellationToken);
        if (!acceptance.Succeeded || acceptance.Value == Guid.Empty)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new AshlarOidcInvitationRegistrationResult(MapInvitationFailure(acceptance), Assertion: assertion, InvitationAcceptance: acceptance);
        }

        var link = await _credentialService.LinkCredentialAsync(
            acceptance.Value,
            assertion,
            new OidcAuthenticationProvider(principal.Provider.ProviderName),
            credentialValue: null,
            credentialMetadata: null,
            cancellationToken: cancellationToken);

        if (!link.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new AshlarOidcInvitationRegistrationResult(MapLinkFailure(link), acceptance.Value, assertion, acceptance, link);
        }

        await transaction.CommitAsync(cancellationToken);
        return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.Registered, acceptance.Value, assertion, acceptance, link);
    }

    private AshlarOidcProviderOptions? GetOidcProvider(string providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName))
        {
            return null;
        }

        var normalizedProviderName = AshlarOAuthOptions.NormalizeProviderName(providerName);
        return _oauthOptions.CurrentValue.OidcProviders.TryGetValue(normalizedProviderName, out var provider) ? provider : null;
    }

    private static AshlarOidcInvitationRegistrationStatus MapInvitationFailure(Result<Guid> result)
    {
        return result.FailureCode?.Value switch
        {
            AshlarFailureCodes.InvalidInvitationValue => AshlarOidcInvitationRegistrationStatus.InvalidInvitation,
            AshlarFailureCodes.RateLimitedValue => AshlarOidcInvitationRegistrationStatus.RateLimited,
            _ => AshlarOidcInvitationRegistrationStatus.Failed
        };
    }

    private static AshlarOidcInvitationRegistrationStatus MapInvitationPreviewFailure(Result<InvitationAcceptancePreview> result)
    {
        return result.FailureCode?.Value switch
        {
            AshlarFailureCodes.RateLimitedValue => AshlarOidcInvitationRegistrationStatus.RateLimited,
            AshlarFailureCodes.InvalidInvitationValue => AshlarOidcInvitationRegistrationStatus.InvalidInvitation,
            _ when result.Succeeded => AshlarOidcInvitationRegistrationStatus.InvalidInvitation,
            _ => AshlarOidcInvitationRegistrationStatus.Failed
        };
    }

    private static AshlarOidcInvitationRegistrationStatus MapLinkFailure(Result result)
    {
        return result.FailureCode?.Value switch
        {
            AshlarFailureCodes.AlreadyLinkedToSelfValue => AshlarOidcInvitationRegistrationStatus.AlreadyLinked,
            AshlarFailureCodes.AlreadyLinkedToOtherValue => AshlarOidcInvitationRegistrationStatus.AlreadyLinkedToAnotherUser,
            AshlarFailureCodes.InvalidProviderKeyValue => AshlarOidcInvitationRegistrationStatus.InvalidPrincipal,
            _ => AshlarOidcInvitationRegistrationStatus.LinkFailed
        };
    }

    private static AshlarExternalProvider CreateExternalProvider(AshlarOidcProviderOptions provider)
    {
        return new AshlarExternalProvider(
            ProviderType.Oidc,
            provider.ProviderName,
            provider.SchemeName,
            provider.ProviderKeyMode);
    }
}
