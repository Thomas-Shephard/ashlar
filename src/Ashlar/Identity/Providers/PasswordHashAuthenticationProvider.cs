using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers;

public abstract class PasswordHashAuthenticationProvider(PasswordHasherSelector hasherSelector) : IAuthenticationProvider
{
    protected PasswordHasherSelector HasherSelector { get; } = hasherSelector ?? throw new ArgumentNullException(nameof(hasherSelector));

    public abstract AuthenticationProviderKey Key { get; }
    public bool ProtectsCredentials => false;

    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        return userId.ToString("D");
    }

    public string PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawValue);
        return PasswordCredentialHashing.HashToBase64(HasherSelector, rawValue);
    }

    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (!SupportsAssertion(assertion) || string.IsNullOrWhiteSpace(context.Email))
        {
            return null;
        }

        return await repository.GetUserByEmailAsync(context.Email, context.TenantId, cancellationToken);
    }

    protected abstract bool SupportsAssertion(IAuthenticationAssertion assertion);
    public abstract Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);
}
