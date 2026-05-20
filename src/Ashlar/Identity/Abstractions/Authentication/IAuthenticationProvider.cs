
namespace Ashlar.Identity.Abstractions.Authentication;

/// <summary>
/// Defines the contract for authentication provider operations.
/// </summary>
public interface IAuthenticationProvider
{
    /// <summary>
    /// Gets the canonical identity for this provider implementation.
    /// </summary>
    AuthenticationProviderKey Key { get; }

    /// <summary>
    /// Gets a value indicating whether the credentials managed by this provider should be protected (encrypted) by the identity service.
    /// Defaults to <c><see langword="true" /></c>.
    /// </summary>
    bool ProtectsCredentials => true;

    /// <summary>
    /// Gets the typical length of a credential value for this provider.
    /// Used to generate timing-safe dummy values for protection.
    /// </summary>
    int TypicalCredentialLength => 256;

    /// <summary>
    /// Gets the unique key for the user within this provider.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="userId">The user id value.</param>
    /// <returns>The operation result.</returns>
    string GetProviderKey(IAuthenticationAssertion assertion, Guid userId);

    /// <summary>
    /// Prepares a raw credential value for storage.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="rawValue">The raw value value.</param>
    /// <returns>The operation result.</returns>
    string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue);

    /// <summary>
    /// Attempts to resolve the user associated with the given assertion.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="context">The context value.</param>
    /// <param name="repository">The repository value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the authentication against the provided credential.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the credential associated with the given assertion and user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="context">The authentication context value.</param>
    /// <param name="repository">The repository value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<UserCredential?> ResolveCredentialAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        AuthenticationContext? context,
        IIdentityRepository repository,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult<UserCredential?>(null);
    }
}

/// <summary>
/// Represents the result of an authentication attempt.
/// </summary>
/// <param name="Status">The status value.</param>
/// <param name="Claims">The claims value.</param>
/// <param name="NewCredentialValue">The new credential value value.</param>
/// <param name="NewMetadata">The new metadata value.</param>
/// <param name="IsCredentialConsumed">The is credential consumed value.</param>
/// <param name="CredentialUpdateRequirement">The credential update requirement value.</param>
public sealed record AuthenticationResult(
    AuthenticationResultStatus Status,
    IDictionary<string, string>? Claims = null,
    string? NewCredentialValue = null,
    string? NewMetadata = null,
    bool IsCredentialConsumed = false,
    CredentialUpdateRequirement CredentialUpdateRequirement = CredentialUpdateRequirement.BestEffort);

/// <summary>
/// Represents the outcome of an authentication attempt.
/// </summary>
public enum AuthenticationResultStatus
{
    /// <summary>
    /// Represents the failed value.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Represents the succeeded value.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// Represents the succeeded with credential update value.
    /// </summary>
    SucceededWithCredentialUpdate = 2,
    /// <summary>
    /// Represents the mfa required value.
    /// </summary>
    MfaRequired = 3
}

/// <summary>
/// Defines the requirement level for persisting credential updates.
/// </summary>
public enum CredentialUpdateRequirement
{
    /// <summary>
    /// The update is best-effort. Failure to persist the update will not fail the authentication.
    /// </summary>
    BestEffort = 0,

    /// <summary>
    /// The update is security-critical. Failure to persist the update will fail the authentication.
    /// </summary>
    Required = 1
}
