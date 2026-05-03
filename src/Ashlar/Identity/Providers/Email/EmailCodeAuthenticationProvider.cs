using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Email;

public sealed class EmailCodeAuthenticationProvider(PasswordHasherSelector hasherSelector) : PasswordHashAuthenticationProvider(hasherSelector)
{
    public const string CredentialPurpose = "email-sign-in";

    public override AuthenticationProviderKey Key => AuthenticationProviderKey.EmailCode;

    protected override bool SupportsAssertion(IAuthenticationAssertion assertion) => assertion is EmailCodeAssertion;

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
