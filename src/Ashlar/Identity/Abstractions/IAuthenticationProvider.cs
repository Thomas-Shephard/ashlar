using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationProvider
{
    /// <summary>
    /// Gets the canonical identity for this provider implementation.
    /// </summary>
    AuthenticationProviderKey Key { get; }

    /// <summary>
    /// Gets a value indicating whether the credentials managed by this provider should be protected (encrypted) by the identity service.
    /// Defaults to <c>true</c>.
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
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="userId">The user's ID.</param>
    /// <returns>The provider key, or an empty string if it cannot be derived.</returns>
    string GetProviderKey(IAuthenticationAssertion assertion, Guid userId);

    /// <summary>
    /// Prepares a raw credential value for storage.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="rawValue">The raw credential value.</param>
    /// <returns>The prepared credential value.</returns>
    string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue);

    /// <summary>
    /// Attempts to resolve the user associated with the given assertion.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="context">The authentication context. Providers may use only the fields they need.</param>
    /// <param name="repository">The identity repository.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The user if found, otherwise <c>null</c>.</returns>
    Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the authentication against the provided credential.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="credential">The user's credential.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The result of the authentication.</returns>
    Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the credential associated with the given assertion and user.
    /// </summary>
    /// <param name="userId">The user's ID.</param>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="repository">The identity repository.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The credential if found, otherwise <c>null</c>.</returns>
    Task<UserCredential?> ResolveCredentialAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IIdentityRepository repository,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult<UserCredential?>(null);
    }
}

/// <summary>
/// Represents the result of an authentication attempt.
/// </summary>
/// <param name="Status">The authentication status.</param>
/// <param name="Claims">Optional claims returned by the provider.</param>
/// <param name="NewCredentialValue">The new credential value if an update is required.</param>
/// <param name="NewMetadata">The new metadata to store with the credential.</param>
/// <param name="IsCredentialConsumed">Indicates whether the credential was consumed (e.g. one-time token) and should be deleted.</param>
/// <param name="CredentialUpdateRequirement">The requirement for persisting credential updates. Defaults to <see cref="CredentialUpdateRequirement.BestEffort"/>.</param>
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
    Failed = 0,
    Succeeded = 1,
    SucceededWithCredentialUpdate = 2
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
