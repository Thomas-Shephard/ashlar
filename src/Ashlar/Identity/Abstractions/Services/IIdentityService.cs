namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Coordinates user lookup and authentication provider execution.
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// Gets the authentication providers registered with the identity service.
    /// </summary>
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    /// <summary>
    /// Finds a user by email address within an optional tenant boundary using Ashlar's normalized lookup form.
    /// </summary>
    /// <param name="email">The email address to look up.</param>
    /// <param name="tenantId">The tenant boundary for the lookup, or <see langword="null" /> for tenantless users.</param>
    /// <param name="cancellationToken">A token that can cancel email lookup.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a user by an authentication provider credential key.
    /// </summary>
    /// <param name="provider">The authentication provider that owns the credential.</param>
    /// <param name="providerKey">The provider-specific credential key.</param>
    /// <param name="cancellationToken">A token that can cancel provider-key lookup.</param>
    /// <returns>The matching user, or <see langword="null" /> when no user exists.</returns>
    Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates an assertion with the matching authentication provider.
    /// </summary>
    /// <param name="context">Request context used for auditing, tenant lookup, and rate limiting.</param>
    /// <param name="assertion">Credentials or provider assertion to authenticate. Treat as sensitive unless the provider documents otherwise.</param>
    /// <param name="cancellationToken">A token that can cancel provider authentication.</param>
    /// <returns>The authentication response. This does not by itself issue an application session.</returns>
    Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);
}

/// <summary>
/// Lists the outcomes of a credential authentication attempt.
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
    /// Authentication succeeded and the provider requested a stored credential update.
    /// </summary>
    SuccessWithCredentialUpdate = 2,
    /// <summary>
    /// Authentication is disabled for the user or credential.
    /// </summary>
    Disabled = 3,
    /// <summary>
    /// Authentication requires an MFA handshake before completion.
    /// </summary>
    MfaRequired = 4,
    /// <summary>
    /// Authentication was blocked by rate limiting.
    /// </summary>
    RateLimited = 5
}

/// <summary>
/// Result returned by an authentication attempt.
/// </summary>
/// <param name="Succeeded">Whether authentication completed successfully.</param>
/// <param name="User">The authenticated user when available.</param>
/// <param name="Status">Outcome of the credential authentication attempt.</param>
/// <param name="Claims">Additional claims produced by the authentication provider.</param>
/// <param name="CredentialUpdatePersisted">Whether a provider-requested credential update was actually persisted during authentication.</param>
/// <remarks>
/// Creates an authentication response.
/// </remarks>
public sealed class AuthenticationResponse(
    bool Succeeded,
    IUser? User = null,
    AuthenticationStatus Status = AuthenticationStatus.Failed,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims = null,
    bool CredentialUpdatePersisted = false)
{

    /// <summary>Gets whether authentication completed successfully.</summary>
    public bool Succeeded { get; } = Succeeded;
    /// <summary>Gets the authenticated user when available.</summary>
    public IUser? User { get; } = User;
    /// <summary>Gets the outcome of the credential authentication attempt.</summary>
    public AuthenticationStatus Status { get; } = Status;
    /// <summary>Gets additional claims produced by the authentication provider.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims { get; } = Claims;
    /// <summary>Gets whether a provider-requested credential update was persisted.</summary>
    public bool CredentialUpdatePersisted { get; } = CredentialUpdatePersisted;

    internal StepUpSessionMarkingProof? StepUpSessionMarkingProof { get; init; }
}
