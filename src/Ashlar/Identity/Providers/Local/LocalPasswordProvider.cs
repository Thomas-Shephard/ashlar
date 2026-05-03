using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Local;

public sealed class LocalPasswordProvider(PasswordHasherSelector hasherSelector) : PasswordHashAuthenticationProvider(hasherSelector)
{
    public override AuthenticationProviderKey Key => AuthenticationProviderKey.Local;

    protected override bool SupportsAssertion(IAuthenticationAssertion assertion) => assertion is LocalPasswordAssertion;

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
