using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Models.Credentials;
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
    private readonly ICredentialRepository _credentialRepository;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IOptionsMonitor<AshlarOAuthOptions> _oauthOptions;
    private readonly IOidcInvitationEmailMatchPolicy _emailMatchPolicy;
    private readonly ISecurityEventSink? _securityEventSink;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the OIDC invitation registration service.
    /// </summary>
    /// <param name="invitationService">The invitation service.</param>
    /// <param name="credentialRepository">Credential repository used inside the invitation acceptance transaction.</param>
    /// <param name="transactionProvider">The transaction provider.</param>
    /// <param name="oauthOptions">The OAuth options monitor.</param>
    /// <param name="emailMatchPolicy">The invitation email match policy.</param>
    /// <param name="securityEventSink">Security event sink used to audit the credential linked by the invitation flow.</param>
    /// <param name="timeProvider">Clock used for emitted security events.</param>
    internal AshlarOidcInvitationRegistrationService(
        IInvitationService invitationService,
        ICredentialRepository credentialRepository,
        IAshlarTransactionProvider transactionProvider,
        IOptionsMonitor<AshlarOAuthOptions> oauthOptions,
        IOidcInvitationEmailMatchPolicy emailMatchPolicy,
        ISecurityEventSink? securityEventSink = null,
        TimeProvider? timeProvider = null)
    {
        _invitationService = invitationService ?? throw new ArgumentNullException(nameof(invitationService));
        _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _oauthOptions = oauthOptions ?? throw new ArgumentNullException(nameof(oauthOptions));
        _emailMatchPolicy = emailMatchPolicy ?? throw new ArgumentNullException(nameof(emailMatchPolicy));
        _securityEventSink = securityEventSink;
        _timeProvider = timeProvider ?? TimeProvider.System;
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
        var (matched, properties) = AshlarExternalProviderResolver.MatchProvider(result, externalProvider);
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

        var link = await LinkAcceptedInvitationCredentialAsync(
            acceptance.Value,
            assertion,
            new OidcAuthenticationProvider(principal.Provider.ProviderName),
            preview.Value.TenantId,
            context,
            cancellationToken: cancellationToken);

        if (!link.Succeeded)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new AshlarOidcInvitationRegistrationResult(MapLinkFailure(link), acceptance.Value, assertion, acceptance, link);
        }

        await transaction.CommitAsync(cancellationToken);
        return new AshlarOidcInvitationRegistrationResult(AshlarOidcInvitationRegistrationStatus.Registered, acceptance.Value, assertion, acceptance, link);
    }

    private async Task<Result> LinkAcceptedInvitationCredentialAsync(
        Guid userId,
        ExternalIdentityAssertion assertion,
        OidcAuthenticationProvider provider,
        Guid? tenantId,
        AuthenticationContext? context,
        CancellationToken cancellationToken)
    {
        var providerKey = provider.GetProviderKey(assertion, userId);
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            await RecordCredentialLinkedAsync(
                userId,
                tenantId,
                context,
                provider.Key,
                SecurityEventOutcomes.Failure,
                AshlarFailureCodes.InvalidProviderKey.Value,
                credentialId: null,
                cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidProviderKey);
        }

        var credentialId = Guid.NewGuid();
        try
        {
            var existingCredential = await _credentialRepository.GetCredentialForUserAsync(
                userId,
                provider.Key.Type,
                provider.Key.Name,
                providerKey,
                cancellationToken);
            if (existingCredential != null)
            {
                await RecordCredentialLinkedAsync(
                    userId,
                    tenantId,
                    context,
                    provider.Key,
                    SecurityEventOutcomes.Failure,
                    AshlarFailureCodes.AlreadyLinkedToSelf.Value,
                    credentialId: null,
                    cancellationToken);
                return Result.Failure(AshlarFailureCodes.AlreadyLinkedToSelf);
            }

            await _credentialRepository.CreateOrReplaceCredentialAsync(new UserCredential
            {
                Id = credentialId,
                UserId = userId,
                ProviderType = provider.Key.Type,
                ProviderName = provider.Key.Name,
                ProviderKey = providerKey,
                Version = Guid.NewGuid().ToString("N"),
                CreatedAt = _timeProvider.GetUtcNow(),
                Status = CredentialStatus.Active
            }, cancellationToken);
            await RecordCredentialLinkedAsync(
                userId,
                tenantId,
                context,
                provider.Key,
                SecurityEventOutcomes.Success,
                failureReason: null,
                credentialId,
                cancellationToken);
            return Result.Success();
        }
        catch (CredentialProviderKeyConflictException)
        {
            await RecordCredentialLinkedAsync(
                userId,
                tenantId,
                context,
                provider.Key,
                SecurityEventOutcomes.Failure,
                AshlarFailureCodes.AlreadyLinkedToOther.Value,
                credentialId: null,
                cancellationToken);
            return Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther);
        }
    }

    private async Task RecordCredentialLinkedAsync(
        Guid userId,
        Guid? tenantId,
        AuthenticationContext? context,
        AuthenticationProviderKey provider,
        string outcome,
        string? failureReason,
        Guid? credentialId,
        CancellationToken cancellationToken)
    {
        if (_securityEventSink == null)
        {
            return;
        }

        await _securityEventSink.RecordAsync(new AshlarSecurityEvent
        {
            Id = Guid.NewGuid(),
            EventType = AshlarSecurityEventTypes.CredentialLinked,
            OccurredAt = _timeProvider.GetUtcNow(),
            UserId = userId,
            TenantId = tenantId ?? context?.TenantId,
            ActorUserId = context?.UserId,
            Provider = provider,
            IpAddress = context?.IpAddress,
            UserAgent = context?.UserAgent,
            CorrelationId = context?.CorrelationId,
            Outcome = outcome,
            FailureReason = failureReason,
            Properties = credentialId.HasValue
                ? new Dictionary<string, string> { ["credential_id"] = credentialId.Value.ToString() }
                : null
        }, cancellationToken);
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
