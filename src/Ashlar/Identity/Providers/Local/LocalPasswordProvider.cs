using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Local;

/// <summary>
/// Provides local password provider behavior.
/// </summary>
/// <param name="hasherSelector">The password hasher selector.</param>
public sealed class LocalPasswordProvider(PasswordHasherSelector hasherSelector) : PasswordHashAuthenticationProvider(hasherSelector)
{
    /// <summary>
    /// Gets or sets the key value.
    /// </summary>
    public override AuthenticationProviderKey Key => AuthenticationProviderKey.Local;

    /// <summary>
    /// Executes the supports assertion operation.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <returns>The operation result.</returns>
    protected override bool SupportsAssertion(IAuthenticationAssertion assertion) => assertion is LocalPasswordAssertion;

    /// <summary>
    /// Performs the authenticate <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credential">The credential value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
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


