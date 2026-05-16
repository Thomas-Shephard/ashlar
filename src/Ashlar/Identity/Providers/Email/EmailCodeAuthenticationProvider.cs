using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Email;

/// <summary>
/// Provides email code authentication provider behavior.
/// </summary>
/// <param name="hasherSelector">The password hasher selector.</param>
public sealed class EmailCodeAuthenticationProvider(PasswordHasherSelector hasherSelector) : PasswordHashAuthenticationProvider(hasherSelector)
{
    /// <summary>
    /// Defines the credential purpose value.
    /// </summary>
    public const string CredentialPurpose = "email-sign-in";

    /// <summary>
    /// Gets or sets the key value.
    /// </summary>
    public override AuthenticationProviderKey Key => AuthenticationProviderKey.EmailCode;

    /// <summary>
    /// Executes the supports assertion operation.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <returns>The operation result.</returns>
    protected override bool SupportsAssertion(IAuthenticationAssertion assertion) => assertion is EmailCodeAssertion;

    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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
