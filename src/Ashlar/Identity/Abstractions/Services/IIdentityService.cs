namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Coordinates authentication provider execution.
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// Gets the authentication providers registered with the identity service.
    /// </summary>
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

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
public sealed class AuthenticationResponse
{
    /// <summary>Creates an authentication response.</summary>
    /// <param name="User">The authenticated user when available.</param>
    /// <param name="Status">Outcome of the credential authentication attempt.</param>
    /// <param name="Claims">Additional claims produced by the authentication provider.</param>
    /// <param name="CredentialUpdatePersisted">Whether a provider-requested credential update was persisted.</param>
    public AuthenticationResponse(
        IUser? User = null,
        AuthenticationStatus Status = AuthenticationStatus.Failed,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims = null,
        bool CredentialUpdatePersisted = false)
    {
        if (!Enum.IsDefined(Status))
        {
            throw new ArgumentOutOfRangeException(nameof(Status));
        }

        if (CredentialUpdatePersisted && Status != AuthenticationStatus.SuccessWithCredentialUpdate)
        {
            throw new ArgumentException("A persisted credential update requires the corresponding success status.", nameof(CredentialUpdatePersisted));
        }

        if (User is null && Status is AuthenticationStatus.Success or AuthenticationStatus.SuccessWithCredentialUpdate or AuthenticationStatus.MfaRequired)
        {
            throw new ArgumentNullException(nameof(User), "Successful and MFA-required responses require a user.");
        }

        this.User = User;
        this.Status = Status;
        this.Claims = Claims;
        this.CredentialUpdatePersisted = CredentialUpdatePersisted;
    }

    /// <summary>Gets whether authentication completed successfully.</summary>
    public bool Succeeded => Status is AuthenticationStatus.Success or AuthenticationStatus.SuccessWithCredentialUpdate;
    /// <summary>Gets the authenticated user when available.</summary>
    public IUser? User { get; }
    /// <summary>Gets the authenticated user.</summary>
    /// <returns>The authenticated user.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the response has no user.</exception>
    public IUser GetUser() =>
        User ?? throw new InvalidOperationException("The authentication response does not contain a user.");
    /// <summary>Gets the outcome of the credential authentication attempt.</summary>
    public AuthenticationStatus Status { get; }
    /// <summary>Gets additional claims produced by the authentication provider.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? Claims { get; }
    /// <summary>Gets whether a provider-requested credential update was persisted.</summary>
    public bool CredentialUpdatePersisted { get; }

    internal StepUpSessionMarkingProof? StepUpSessionMarkingProof { get; init; }
}
