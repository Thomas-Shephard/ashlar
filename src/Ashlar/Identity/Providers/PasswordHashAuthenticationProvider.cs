using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers;

/// <summary>
/// Provides password hash authentication provider behavior.
/// </summary>
/// <param name="hasherSelector">The hasher selector value.</param>
public abstract class PasswordHashAuthenticationProvider(PasswordHasherSelector hasherSelector) : IAuthenticationProvider
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    protected PasswordHasherSelector HasherSelector { get; } = hasherSelector ?? throw new ArgumentNullException(nameof(hasherSelector));

    /// <summary>
    /// Gets or sets the key value.
    /// </summary>
    public abstract AuthenticationProviderKey Key { get; }
    /// <summary>
    /// Gets or sets the protects credentials value.
    /// </summary>
    public bool ProtectsCredentials => false;

    /// <summary>
    /// Performs the get provider key operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="userId">The user id value.</param>
    /// <returns>The operation result.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        return userId.ToString("D");
    }

    /// <summary>
    /// Performs the prepare credential value operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="rawValue">The raw value value.</param>
    /// <returns>The operation result.</returns>
    public string PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawValue);
        return PasswordCredentialHashing.HashToBase64(HasherSelector, rawValue);
    }

    /// <summary>
    /// Performs the find user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="repository">The repository value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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

    /// <summary>
    /// Performs the supports assertion operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <returns>The operation result.</returns>
    protected abstract bool SupportsAssertion(IAuthenticationAssertion assertion);
    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    public abstract Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);
}


