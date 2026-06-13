using System.Security.Claims;
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
    /// <returns>The invitation registration result.</returns>
    public async Task<AshlarOidcInvitationRegistrationResult> CompleteOidcInvitationRegistrationAsync(
        HttpContext httpContext,
        string? invitationToken,
        string providerName,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
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

        if (!MatchesProvider(result, provider))
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.ProviderMismatch);
        }

        return await RegisterOidcInvitationAsync(invitationToken, providerName, result.Principal, displayName, context, cancellationToken);
    }

    /// <summary>
    /// Completes invitation registration from a completed ASP.NET Core external authentication result.
    /// </summary>
    /// <param name="invitationToken">The invitation token.</param>
    /// <param name="providerName">The configured Ashlar OIDC provider name.</param>
    /// <param name="authenticateResult">The completed external authentication result.</param>
    /// <param name="displayName">Optional user display name for invitation acceptance.</param>
    /// <param name="context">Optional Ashlar authentication context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The invitation registration result.</returns>
    public Task<AshlarOidcInvitationRegistrationResult> RegisterOidcInvitationAsync(
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

        if (!MatchesProvider(authenticateResult, provider))
        {
            return Task.FromResult(new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.ProviderMismatch));
        }

        return RegisterOidcInvitationAsync(invitationToken, providerName, authenticateResult.Principal, displayName, context, cancellationToken);
    }

    /// <summary>
    /// Accepts an invitation using an already validated OpenID Connect principal and links the OIDC subject to the accepted user.
    /// </summary>
    /// <param name="invitationToken">The invitation token.</param>
    /// <param name="providerName">The configured Ashlar OIDC provider name.</param>
    /// <param name="principal">The validated external principal. Do not pass principals built from request data or unvalidated tokens.</param>
    /// <param name="displayName">Optional user display name for invitation acceptance.</param>
    /// <param name="context">Optional Ashlar authentication context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The invitation registration result.</returns>
    public async Task<AshlarOidcInvitationRegistrationResult> RegisterOidcInvitationAsync(
        string? invitationToken,
        string providerName,
        ClaimsPrincipal principal,
        string? displayName = null,
        AuthenticationContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var providerOptions = GetOidcProvider(providerName);
        if (providerOptions == null)
        {
            return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.UnsupportedProvider);
        }

        ExternalIdentityAssertion assertion;
        try
        {
            assertion = OidcExternalIdentityAssertionMapper.Map(providerOptions.ProviderName, principal, providerOptions.ProviderKeyMode);
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

        var emailMatch = _emailMatchPolicy.Validate(new OidcInvitationEmailMatchContext(providerOptions.ProviderName, principal, preview.Value));
        if (!emailMatch.Succeeded)
        {
            return new AshlarOidcInvitationRegistrationResult(emailMatch.Status ?? AshlarOidcInvitationRegistrationStatus.Failed, Assertion: assertion);
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
            new OidcAuthenticationProvider(providerOptions.ProviderName),
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

    private static bool MatchesProvider(AuthenticateResult result, AshlarOidcProviderOptions provider)
    {
        var externalProvider = new AshlarExternalProvider(
            ProviderType.Oidc,
            provider.ProviderName,
            provider.SchemeName,
            provider.ProviderKeyMode);
        return AshlarExternalProviderResolver.MatchesProvider(result, externalProvider);
    }
}
