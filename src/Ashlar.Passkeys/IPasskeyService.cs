namespace Ashlar.Passkeys;

/// <summary>
/// Coordinates passkey registration, authentication, and credential management flows.
/// </summary>
/// <remarks>
/// Factor flows use Ashlar MFA handshakes. Configure identity, credential, passkey challenge, and authentication handshake
/// repositories when resolving this service.
/// </remarks>
public interface IPasskeyService
{
    /// <summary>
    /// Starts a passkey registration ceremony.
    /// </summary>
    /// <param name="request">The registration request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The browser ceremony options.</returns>
    /// <remarks>
    /// The target user must exist, be in the requested tenant scope, and have an account state that can sign in.
    /// Omitted tenant scope is treated as global scope.
    /// </remarks>
    Task<PasskeyCeremonyOptions> StartRegistrationAsync(StartPasskeyRegistrationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Completes a passkey registration ceremony.
    /// </summary>
    /// <param name="request">The completion request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// The challenge user is reloaded before credential persistence. The expected user, request tenant, challenge
    /// tenant, and stored user tenant must all match, and the account must still be able to sign in.
    /// </remarks>
    Task<Result> CompleteRegistrationAsync(CompletePasskeyRegistrationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Starts a passkey authentication ceremony.
    /// </summary>
    /// <param name="request">The authentication request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The browser ceremony options when challenge creation is allowed.</returns>
    Task<Result<PasskeyCeremonyOptions>> StartAuthenticationAsync(StartPasskeyAuthenticationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Completes a passkey authentication ceremony.
    /// </summary>
    /// <param name="request">The completion request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authentication result.</returns>
    Task<PasskeyAuthenticationResult> CompleteAuthenticationAsync(CompletePasskeyAuthenticationRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Starts a passkey MFA factor ceremony for an existing handshake.
    /// </summary>
    /// <param name="request">The factor request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The browser ceremony options when the handshake can use passkeys.</returns>
    Task<Result<PasskeyCeremonyOptions>> StartFactorAsync(StartPasskeyFactorRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Completes a passkey MFA factor ceremony for an existing handshake.
    /// </summary>
    /// <param name="request">The completion request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authentication result.</returns>
    Task<PasskeyAuthenticationResult> CompleteFactorAsync(CompletePasskeyFactorRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Lists passkeys registered for a user.
    /// </summary>
    /// <param name="userId">The user id.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The registered passkeys.</returns>
    Task<IReadOnlyList<PasskeyCredentialSummary>> ListAsync(Guid userId, CancellationToken cancellationToken = default);
    /// <summary>
    /// Renames a passkey display name.
    /// </summary>
    /// <param name="request">The rename request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result.</returns>
    Task<Result> RenameAsync(RenamePasskeyRequest request, CancellationToken cancellationToken = default);
    /// <summary>
    /// Revokes a passkey credential.
    /// </summary>
    /// <param name="request">The revocation request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The operation result.</returns>
    Task<Result> RevokeAsync(RevokePasskeyRequest request, CancellationToken cancellationToken = default);
}
