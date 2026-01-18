using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationProvider
{
    /// <summary>
    /// Gets the type of provider supported by this implementation.
    /// </summary>
    ProviderType SupportedType { get; }

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
    /// Gets the provider name from the assertion.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <returns>The provider name.</returns>
    string GetProviderName(IAuthenticationAssertion assertion)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        return SupportedType.Value;
    }

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
    /// <param name="email">The email provided during login. This may be <c>null</c> or ignored if the provider resolves the user solely from the assertion (e.g., external identity providers).</param>
    /// <param name="tenantId">The optional tenant ID.</param>
    /// <param name="repository">The identity repository.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The user if found, otherwise <c>null</c>.</returns>
    Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, string? email, Guid? tenantId, IIdentityRepository repository, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the authentication against the provided credential.
    /// </summary>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="credential">The user's credential.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The result of the authentication.</returns>
    Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);
}

/// <summary>
/// Represents the result of an authentication attempt.
/// </summary>
/// <param name="Result">The result of the password verification.</param>
/// <param name="Claims">Optional claims returned by the provider.</param>
/// <param name="ShouldUpdateCredential">Indicates whether the credential should be updated (e.g. password rehash).</param>
/// <param name="NewCredentialValue">The new credential value if an update is required.</param>
/// <param name="NewMetadata">The new metadata to store with the credential.</param>
/// <param name="IsCredentialConsumed">Indicates whether the credential was consumed (e.g. one-time token) and should be deleted.</param>
public sealed record AuthenticationResult(
    PasswordVerificationResult Result,
    IDictionary<string, string>? Claims = null,
    bool ShouldUpdateCredential = false,
    string? NewCredentialValue = null,
    string? NewMetadata = null,
    bool IsCredentialConsumed = false);
