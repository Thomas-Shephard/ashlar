
namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Coordinates user lookup, credential linking, and authentication provider execution.
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// Gets the authentication providers registered with the identity service.
    /// </summary>
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    /// <summary>
    /// Finds a user by normalized email address and optional tenant.
    /// </summary>
    /// <param name="email">The email address to look up.</param>
    /// <param name="tenantId">The tenant to search, or <see langword="null" /> for a global lookup.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a user by an authentication provider credential key.
    /// </summary>
    /// <param name="provider">The authentication provider that owns the credential.</param>
    /// <param name="providerKey">The provider-specific credential key.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an assertion with the matching authentication provider.
    /// </summary>
    /// <param name="context">Request context used for auditing, tenant lookup, and rate limiting.</param>
    /// <param name="assertion">The credentials or provider assertion to authenticate.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The authentication response.</returns>
    Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a user in the configured identity repository.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The created user.</returns>
    Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Links a credential for the specified user using the provider selected by the assertion.
    /// </summary>
    /// <param name="userId">The user that will own the credential.</param>
    /// <param name="assertion">The assertion used to derive the provider key and metadata.</param>
    /// <param name="credentialValue">The raw credential value to protect before storage, when required by the provider.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>A result describing whether the credential was linked.</returns>
    Task<Result> LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Defines the available authentication status values.
/// </summary>
public enum AuthenticationStatus
{
    /// <summary>
    /// Authentication failed.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Authentication succeeded.
    /// </summary>
    Success = 1,
    /// <summary>
    /// Authentication succeeded and the stored credential should be updated.
    /// </summary>
    SuccessWithCredentialUpdate = 2,
    /// <summary>
    /// Authentication is disabled for the user or credential.
    /// </summary>
    Disabled = 3,
    /// <summary>
    /// Authentication requires an MFA handshake before completion.
    /// </summary>
    MfaRequired = 4
}

/// <summary>
/// Result returned by an authentication attempt.
/// </summary>
/// <param name="Succeeded">Whether authentication completed successfully.</param>
/// <param name="User">The authenticated user when available.</param>
/// <param name="Status">The authentication outcome.</param>
/// <param name="Claims">Additional claims produced by the authentication provider.</param>
public sealed record AuthenticationResponse(
    bool Succeeded,
    IUser? User = null,
    AuthenticationStatus Status = AuthenticationStatus.Failed,
    IDictionary<string, string>? Claims = null);
