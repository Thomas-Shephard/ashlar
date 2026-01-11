using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IIdentityService
{
    IEnumerable<ProviderType> SupportedProviderTypes { get; }
    Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
    Task<IUser?> FindByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default);

    Task<AuthenticationResponse> LoginAsync(string email, IAuthenticationAssertion assertion, Guid? tenantId = null, CancellationToken cancellationToken = default);

    Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default);
}

public enum AuthenticationStatus
{
    Failed = 0,
    Success = 1,
    SuccessRehashNeeded = 2,
    Disabled = 3
}

public sealed record AuthenticationResponse(
    bool Succeeded,
    IUser? User = null,
    AuthenticationStatus Status = AuthenticationStatus.Failed,
    IDictionary<string, string>? Claims = null);
