using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Local;

/// <summary>
/// Authenticates local passwords against stored password hashes.
/// </summary>
/// <param name="hasherSelector">Hashing component used to verify submitted passwords and produce upgraded hashes.</param>
public sealed class LocalPasswordProvider(PasswordHasherSelector hasherSelector) : PasswordHashAuthenticationProvider(hasherSelector)
{
    /// <summary>
    /// Gets the local password provider key.
    /// </summary>
    public override AuthenticationProviderKey Key => AuthenticationProviderKey.Local;

    /// <summary>
    /// Determines whether the assertion contains a local password submission.
    /// </summary>
    /// <param name="assertion">Assertion supplied to the authentication pipeline.</param>
    /// <returns><see langword="true" /> when this provider can validate the assertion; otherwise, <see langword="false" />.</returns>
    protected override bool SupportsAssertion(IAuthenticationAssertion assertion) => assertion is LocalPasswordAssertion;

    /// <summary>
    /// Verifies the submitted password against the stored hash.
    /// </summary>
    /// <param name="assertion">Local password assertion containing the plaintext password.</param>
    /// <param name="credential">Stored local password credential containing the encoded hash.</param>
    /// <param name="cancellationToken">Token for aborting authentication work.</param>
    /// <returns>Authentication status and an upgraded credential value when the hash version should be replaced.</returns>
    public override Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not LocalPasswordAssertion passwordAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        byte[]? buffer = PasswordCredentialHashing.DecodeBase64(credential?.CredentialValue);

        ReadOnlySpan<byte> encodedHash = buffer ?? [];

        var result = HasherSelector.VerifyPassword(passwordAssertion.Password, encodedHash);

        if (buffer == null)
        {
            result = PasswordVerificationResult.Failed;
        }

        string? newCredentialValue = null;
        if (result == PasswordVerificationResult.SuccessWithCredentialUpdate)
        {
            newCredentialValue = PasswordCredentialHashing.HashToBase64(HasherSelector, passwordAssertion.Password);
        }

        var status = result switch
        {
            PasswordVerificationResult.Success => AuthenticationResultStatus.Succeeded,
            PasswordVerificationResult.SuccessWithCredentialUpdate => AuthenticationResultStatus.SucceededWithCredentialUpdate,
            _ => AuthenticationResultStatus.Failed
        };

        return Task.FromResult(new AuthenticationResult(status, NewCredentialValue: newCredentialValue));
    }
}
