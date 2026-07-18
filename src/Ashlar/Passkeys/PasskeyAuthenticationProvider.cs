using Microsoft.Extensions.Options;

namespace Ashlar.Passkeys;

/// <summary>
/// Authenticates verified passkey assertions against stored Ashlar credentials.
/// </summary>
/// <param name="options">The passkey options.</param>
public sealed class PasskeyAuthenticationProvider(IOptions<PasskeyOptions> options) : IPrimaryAuthenticationProvider, ISecondaryAuthenticationFactorProvider, IAuthenticationUserResolver
{
    private readonly PasskeyOptions _options = options.Value;

    /// <summary>
    /// Gets the provider key.
    /// </summary>
    public AuthenticationProviderKey Key => _options.ProviderKey;
    /// <summary>
    /// Gets a value indicating whether credentials must be protected before storage.
    /// </summary>
    public bool ProtectsCredentials => false;
    /// <summary>
    /// Gets the expected credential length when one is known.
    /// </summary>
    public int TypicalCredentialLength => 0;
    /// <summary>
    /// Gets the factor family represented by passkeys.
    /// </summary>
    public string FactorType => AuthenticationFactorTypes.Passkey;

    /// <summary>
    /// Determines whether this provider can satisfy a pending factor.
    /// </summary>
    /// <param name="factorType">The required factor type.</param>
    /// <returns><see langword="true" /> when the required factor is passkey-compatible.</returns>
    public bool CanSatisfyFactor(string factorType) => AuthenticationFactorTypes.Matches(FactorType, factorType);

    /// <summary>
    /// Gets the credential lookup key from a passkey assertion.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="userId">The user id.</param>
    /// <returns>The credential lookup key.</returns>
    public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId)
    {
        return PasskeyService.TryReadCapability(assertion, Key, out var credentialId, out _) ? credentialId : string.Empty;
    }

    /// <summary>
    /// Prepares a credential value for storage.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="rawValue">The raw credential value.</param>
    /// <returns>The prepared credential value.</returns>
    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;

    /// <summary>
    /// Finds the user associated with a passkey assertion.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="context">The authentication context.</param>
    /// <param name="users">Read-only user lookup capability.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The user when a matching credential exists.</returns>
    public async Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IUserLookup users, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(users);

        if (!PasskeyService.TryReadCapability(assertion, Key, out var credentialId, out _))
        {
            return null;
        }

        if (context.UserId.HasValue)
        {
            return null;
        }

        return await users.GetUserByProviderKeyAsync(Key.Type, Key.Name, credentialId, cancellationToken);
    }

    /// <summary>
    /// Authenticates a passkey assertion against a stored credential.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="credential">The stored credential.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authentication result.</returns>
    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (!PasskeyService.TryReadCapability(assertion, Key, out _, out var signCount))
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        if (credential == null)
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        if (!PasskeyCredentialMetadataOperations.TryUpdateAssertionMetadata(credential.Metadata, signCount, out var metadata))
        {
            return Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
        }

        return Task.FromResult(new AuthenticationResult(
            AuthenticationResultStatus.SucceededWithCredentialUpdate,
            NewMetadata: metadata,
            CredentialUpdateRequirement: CredentialUpdateRequirement.Required));
    }
}
