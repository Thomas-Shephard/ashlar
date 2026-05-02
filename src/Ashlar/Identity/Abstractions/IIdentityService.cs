using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IIdentityService
{
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
    Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default);

    Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);

    Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default);
}

public enum AuthenticationStatus
{
    Failed = 0,
    Success = 1,
    SuccessWithCredentialUpdate = 2,
    Disabled = 3
}

public sealed record AuthenticationResponse(
    bool Succeeded,
    IUser? User = null,
    AuthenticationStatus Status = AuthenticationStatus.Failed,
    IDictionary<string, string>? Claims = null);
