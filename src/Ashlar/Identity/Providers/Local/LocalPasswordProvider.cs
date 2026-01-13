using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Local;

public sealed class LocalPasswordProvider(PasswordHasherSelector hasherSelector) : IAuthenticationProvider
{
    private readonly PasswordHasherSelector _hasherSelector = hasherSelector ?? throw new ArgumentNullException(nameof(hasherSelector));

    public ProviderType SupportedType => ProviderType.Local;
    public bool IsPrimary => true;
    public bool ProtectsCredentials => false;

    public string GetProviderKey(IAuthenticationAssertion assertion, IUser user)
    {
        return user.Id.ToString("D");
    }

    public string PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawValue);
        return Convert.ToBase64String(_hasherSelector.DefaultHasher.HashPassword(rawValue));
    }

    public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not LocalPasswordAssertion passwordAssertion)
        {
            throw new ArgumentException($"Unsupported assertion type: {assertion.GetType().Name}", nameof(assertion));
        }

        byte[]? buffer = null;
        if (credential?.CredentialValue != null)
        {
            try
            {
                buffer = Convert.FromBase64String(credential.CredentialValue);
            }
            catch (FormatException)
            {
                // Continue to ensure timing safety even if the DB contains malformed data.
                buffer = null;
            }
        }

        ReadOnlySpan<byte> encodedHash = buffer ?? [];

        var result = _hasherSelector.VerifyPassword(passwordAssertion.Password, encodedHash);

        if (buffer == null)
        {
            result = PasswordVerificationResult.Failed;
        }

        string? newCredentialValue = null;
        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            newCredentialValue = Convert.ToBase64String(_hasherSelector.DefaultHasher.HashPassword(passwordAssertion.Password));
        }

        return Task.FromResult(new AuthenticationResult(result, ShouldUpdateCredential: result == PasswordVerificationResult.SuccessRehashNeeded, NewCredentialValue: newCredentialValue));
    }
}
