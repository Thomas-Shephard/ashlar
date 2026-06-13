using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Authenticates single-use email codes stored as credential hashes.
/// </summary>
/// <param name="hasherSelector">Hashing component used to verify submitted codes without exposing stored values.</param>
public sealed class EmailCodeAuthenticationProvider(PasswordHasherSelector hasherSelector) : PasswordHashAuthenticationProvider(hasherSelector)
{
    /// <summary>
    /// Credential purpose assigned to transient email-code credentials.
    /// </summary>
    public const string CredentialPurpose = "email-sign-in";

    /// <summary>
    /// Gets the provider key used for email-code credentials.
    /// </summary>
    public override AuthenticationProviderKey Key => AuthenticationProviderKey.EmailCode;

    /// <summary>
    /// Determines whether the assertion contains an email-code submission.
    /// </summary>
    /// <param name="assertion">Assertion supplied to the authentication pipeline.</param>
    /// <returns><see langword="true" /> when this provider can validate the assertion; otherwise, <see langword="false" />.</returns>
    protected override bool SupportsAssertion(IAuthenticationAssertion assertion) => assertion is EmailCodeAssertion;

    /// <summary>
    /// Validates the submitted code against the stored credential hash.
    /// </summary>
    /// <param name="assertion">Email-code assertion containing the raw submitted code.</param>
    /// <param name="credential">Transient credential whose value contains the stored code hash.</param>
    /// <param name="cancellationToken">Token for aborting authentication work.</param>
    /// <returns>Authentication status indicating whether the code matched and should be consumed.</returns>
    public override Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not EmailCodeAssertion emailCodeAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        byte[]? buffer = null;
        if (credential is { CredentialValue: not null, Purpose: CredentialPurpose })
        {
            buffer = PasswordCredentialHashing.DecodeBase64(credential.CredentialValue);
        }

        var result = HasherSelector.VerifyPassword(emailCodeAssertion.Code, buffer ?? []);
        var status = buffer != null && result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessWithCredentialUpdate
            ? AuthenticationResultStatus.Succeeded
            : AuthenticationResultStatus.Failed;

        return Task.FromResult(new AuthenticationResult(status, IsCredentialConsumed: status == AuthenticationResultStatus.Succeeded));
    }
}
