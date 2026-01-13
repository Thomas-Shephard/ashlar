using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity;

public sealed class IdentityService : IIdentityService
{
    private readonly IIdentityRepository _repository;
    private readonly ICredentialService _credentialService;
    private readonly SessionTicketSerializer _ticketSerializer;
    private readonly IReadOnlyDictionary<ProviderType, IAuthenticationProvider> _providers;

    public IdentityService(
        IIdentityRepository repository,
        IEnumerable<IAuthenticationProvider> providers,
        ICredentialService credentialService,
        SessionTicketSerializer ticketSerializer)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _ticketSerializer = ticketSerializer ?? throw new ArgumentNullException(nameof(ticketSerializer));

        ArgumentNullException.ThrowIfNull(providers);
        var dict = new Dictionary<ProviderType, IAuthenticationProvider>();
        foreach (var provider in providers)
        {
            if (!dict.TryAdd(provider.SupportedType, provider))
            {
                throw new ArgumentException($"Duplicate provider registered for type {provider.SupportedType}", nameof(providers));
            }
        }
        _providers = dict;
    }

    public IEnumerable<ProviderType> SupportedProviderTypes => _providers.Keys;

    public async Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByEmailAsync(email, tenantId, cancellationToken);
    }

    public async Task<IUser?> FindByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        return await _repository.GetUserByProviderKeyAsync(type, providerName, providerKey, cancellationToken);
    }

    public async Task<AuthenticationResponse> LoginAsync(string email, IAuthenticationAssertion assertion, Guid? tenantId = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var (user, credential, unprotectFailed) = await _credentialService.ResolveAsync(email, assertion, tenantId, cancellationToken);

        return await ProcessAuthenticationAsync(user, credential, unprotectFailed, assertion, provider, null, cancellationToken);
    }

    public async Task<AuthenticationResponse> LoginAsync(SessionTicket ticket, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(assertion);

        var handshake = _ticketSerializer.Deserialize(ticket.Value);
        if (handshake == null)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!_providers.TryGetValue(assertion.ProviderType, out var provider))
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var (user, credential, unprotectFailed) = await _credentialService.ResolveAsync(handshake.UserId, assertion, cancellationToken);

        return await ProcessAuthenticationAsync(user, credential, unprotectFailed, assertion, provider, handshake, cancellationToken);
    }

    private async Task<AuthenticationResponse> ProcessAuthenticationAsync(
        IUser? user,
        UserCredential? credential,
        bool unprotectFailed,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        IAuthenticationHandshake? handshake,
        CancellationToken cancellationToken)
    {
        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);

        // Check for failure. We treat user == null or unprotectFailed as failure.
        if (unprotectFailed || result.Result is PasswordVerificationResult.Failed || user == null)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!user.IsActive)
        {
            return new AuthenticationResponse(false, user, AuthenticationStatus.Disabled);
        }

        // Delegate credential usage updates (LastUsedAt, rehashing, metadata) to CredentialService
        await _credentialService.UpdateCredentialUsageAsync(credential, result, provider, cancellationToken);

        var verifiedFactors = handshake?.VerifiedFactors?.ToList() ?? new List<string>();
        if (!verifiedFactors.Contains(assertion.ProviderType.Value))
        {
            verifiedFactors.Add(assertion.ProviderType.Value);
        }

        // Determine if more factors are required
        if (await IsMfaRequiredAsync(user, verifiedFactors, assertion, cancellationToken))
        {
            var newTicket = _ticketSerializer.Serialize(user.Id, verifiedFactors, user is ITenantUser tu ? tu.TenantId : null);
            return new AuthenticationResponse(true, user, AuthenticationStatus.MfaRequired, result.Claims, newTicket, verifiedFactors);
        }

        var status = result.Result == PasswordVerificationResult.SuccessRehashNeeded ? AuthenticationStatus.SuccessRehashNeeded : AuthenticationStatus.Success;
        return new AuthenticationResponse(true, user, status, result.Claims, VerifiedFactors: verifiedFactors);
    }

    public async Task<AuthenticationResponse> CreateVerificationHandshakeAsync(Guid userId, IEnumerable<string>? alreadyVerifiedFactors = null, CancellationToken cancellationToken = default)
    {
        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null || !user.IsActive)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var verifiedFactors = alreadyVerifiedFactors?.ToList() ?? new List<string>();

        if (await IsMfaRequiredAsync(user, verifiedFactors, null, cancellationToken))
        {
            var ticket = _ticketSerializer.Serialize(user.Id, verifiedFactors, user is ITenantUser tu ? tu.TenantId : null);
            return new AuthenticationResponse(true, user, AuthenticationStatus.MfaRequired, SessionTicket: ticket, VerifiedFactors: verifiedFactors);
        }

        return new AuthenticationResponse(true, user, AuthenticationStatus.Success, VerifiedFactors: verifiedFactors);
    }

    private async Task<bool> IsMfaRequiredAsync(IUser user, List<string>? verifiedFactors, IAuthenticationAssertion? assertion, CancellationToken cancellationToken)
    {
        if (assertion != null && _providers.TryGetValue(assertion.ProviderType, out var currentProvider))
        {
             if (currentProvider.BypassesMfa(assertion))
             {
                 return false;
             }
        }

        var factors = verifiedFactors ?? new List<string>();
        bool hasPrimary = false;
        bool hasSecondary = false;

        foreach (var factor in factors)
        {
            if (string.IsNullOrWhiteSpace(factor)) continue;

            ProviderType pt = factor;

            if (_providers.TryGetValue(pt, out var p))
            {
                if (p.IsPrimary) hasPrimary = true;
                if (p.IsSecondary) hasSecondary = true;
            }
        }

        if (!hasPrimary)
        {
            return true;
        }

        var userCredentials = await _repository.GetCredentialsForUserAsync(user.Id, cancellationToken);
        bool hasSecondaryConfigured = userCredentials != null && userCredentials.Any(c => _providers.TryGetValue(c.ProviderType, out var p) && p.IsSecondary);

        if (hasSecondaryConfigured && !hasSecondary)
        {
            return true;
        }

        return false;
    }

    public async Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
    {
        await _repository.CreateUserAsync(user, cancellationToken);
        return user;
    }

    public async Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default)
    {
        await _credentialService.LinkCredentialAsync(userId, assertion, credentialValue, cancellationToken);
    }
}