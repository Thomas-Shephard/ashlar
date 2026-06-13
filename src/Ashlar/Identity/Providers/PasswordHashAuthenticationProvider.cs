using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers;

/// <summary>
/// Base class for authentication providers that validate raw submissions against stored hashes.
/// </summary>
/// <param name="hasherSelector">Hashing component used to verify submissions and produce upgraded hashes.</param>
public abstract class PasswordHashAuthenticationProvider(PasswordHasherSelector hasherSelector) : IPrimaryAuthenticationProvider
{
    /// <summary>
    /// Gets the hashing component used by derived providers.
    /// </summary>
    protected PasswordHasherSelector HasherSelector { get; } = hasherSelector ?? throw new ArgumentNullException(nameof(hasherSelector));

    /// <summary>
    /// Gets the provider key for credentials handled by the derived provider.
    /// </summary>
    public abstract AuthenticationProviderKey Key { get; }
    /// <summary>
    /// Gets a value indicating that derived providers store already-hashed credential payloads.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Uses the user id as the storage key for password-hash credentials.
    /// </summary>
    /// <param name="assertion">Authentication assertion associated with the credential.</param>
    /// <param name="userId">User whose credential is being resolved.</param>
    /// <returns>Stable provider key for the user's password-hash credential.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        return userId.ToString("D");
    }

    /// <summary>
    /// Hashes a raw credential value before persistence.
    /// </summary>
    /// <param name="assertion">Authentication assertion associated with the credential.</param>
    /// <param name="rawValue">Raw credential value. Do not log this value.</param>
    /// <returns>Encoded credential hash safe for persistence.</returns>
    public string PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawValue);
        return PasswordCredentialHashing.HashToBase64(HasherSelector, rawValue);
    }

    /// <summary>
    /// Resolves a user by the email in the authentication context.
    /// </summary>
    /// <param name="assertion">Assertion that must be supported by the derived provider.</param>
    /// <param name="context">Authentication context containing the normalized email and tenant scope.</param>
    /// <param name="repository">User repository used to resolve the account.</param>
    /// <param name="cancellationToken">Token for aborting lookup work.</param>
    /// <returns>The matching user, or <see langword="null" /> when the assertion or email cannot resolve an account.</returns>
    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IUserRepository repository, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(repository);

        if (!SupportsAssertion(assertion) || string.IsNullOrWhiteSpace(context.Email))
        {
            return null;
        }

        return await repository.GetUserByEmailAsync(context.Email, context.TenantId, cancellationToken);
    }

    /// <summary>
    /// Determines whether the derived provider can validate the assertion.
    /// </summary>
    /// <param name="assertion">Assertion supplied to the authentication pipeline.</param>
    /// <returns><see langword="true" /> when the derived provider can validate the assertion; otherwise, <see langword="false" />.</returns>
    protected abstract bool SupportsAssertion(IAuthenticationAssertion assertion);
    /// <summary>
    /// Validates the assertion against the stored credential.
    /// </summary>
    /// <param name="assertion">Assertion containing the raw submission to validate.</param>
    /// <param name="credential">Stored credential containing the encoded hash payload.</param>
    /// <param name="cancellationToken">Token for aborting authentication work.</param>
    /// <returns>Authentication status and any credential hash update requested by the derived provider.</returns>
    public abstract Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);
}
