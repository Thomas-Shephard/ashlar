using System.Text.Json;

namespace Ashlar.Passkeys;

/// <summary>
/// Adapts a WebAuthn/FIDO2 implementation such as fido2-net-lib.
/// </summary>
public interface IPasskeyCeremonyValidator
{
    /// <summary>
    /// Creates registration options for a browser WebAuthn ceremony.
    /// </summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="user">The user registering a passkey.</param>
    /// <param name="displayName">The passkey display name.</param>
    /// <param name="challenge">The Ashlar-managed challenge.</param>
    /// <param name="existingCredentials">Existing passkey credentials for exclusion.</param>
    /// <returns>The serialized registration options.</returns>
    string CreateRegistrationOptions(PasskeyOptions options, IUser user, string displayName, string challenge, IReadOnlyList<UserCredential> existingCredentials);
    /// <summary>
    /// Verifies a registration ceremony response.
    /// </summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="challenge">The stored challenge.</param>
    /// <param name="credentialResponse">The browser credential response.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The verified registration result.</returns>
    Task<PasskeyRegistrationVerificationResult> VerifyRegistrationAsync(PasskeyOptions options, PasskeyChallenge challenge, JsonElement credentialResponse, CancellationToken cancellationToken = default);
    /// <summary>
    /// Creates authentication options for a browser WebAuthn ceremony.
    /// </summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="challenge">The Ashlar-managed challenge.</param>
    /// <param name="allowedCredentials">Allowed credentials for user-scoped flows.</param>
    /// <param name="userVerification">The WebAuthn user verification requirement for this authentication ceremony.</param>
    /// <returns>The serialized authentication options.</returns>
    string CreateAuthenticationOptions(PasskeyOptions options, string challenge, IReadOnlyList<UserCredential> allowedCredentials, string userVerification);
    /// <summary>
    /// Verifies an authentication ceremony response.
    /// </summary>
    /// <param name="options">The passkey options.</param>
    /// <param name="challenge">The stored challenge.</param>
    /// <param name="credential">The stored credential.</param>
    /// <param name="assertionResponse">The browser assertion response.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The verified authentication result.</returns>
    Task<PasskeyAuthenticationVerificationResult> VerifyAuthenticationAsync(PasskeyOptions options, PasskeyChallenge challenge, UserCredential credential, JsonElement assertionResponse, CancellationToken cancellationToken = default);
}
