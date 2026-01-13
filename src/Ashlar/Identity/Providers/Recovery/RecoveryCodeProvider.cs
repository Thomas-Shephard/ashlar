using System.Security.Cryptography;
using System.Text;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Providers.Recovery;

public sealed class RecoveryCodeProvider : IAuthenticationProvider
{
    private readonly IIdentityRepository _repository;

    public RecoveryCodeProvider(IIdentityRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    public ProviderType SupportedType => ProviderType.RecoveryCode;
    public bool IsPrimary => true;
    public bool IsSecondary => true;

    public string? GetProviderKey(IAuthenticationAssertion assertion, IUser user)
    {
         if (assertion is RecoveryCodeAssertion recovery && !string.IsNullOrEmpty(recovery.Code))
         {
             return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(recovery.Code)));
         }
         return null;
    }

    public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue)) return null;
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(rawValue)));
    }

    public async Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default)
    {
        if (assertion is not RecoveryCodeAssertion recoveryAssertion)
        {
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        // We expect the credential to be resolved by the CredentialResolver using the hash of the code.
        if (credential?.CredentialValue == null)
        {
            // Timing parity: always hash the input to prevent response discrepancy timing oracles.
            _ = SHA256.HashData(Encoding.UTF8.GetBytes(recoveryAssertion.Code));
            return new AuthenticationResult(PasswordVerificationResult.Failed);
        }

        var inputHash = SHA256.HashData(Encoding.UTF8.GetBytes(recoveryAssertion.Code));
        
        try 
        {
            var storedHash = Convert.FromBase64String(credential.CredentialValue);
            if (CryptographicOperations.FixedTimeEquals(inputHash, storedHash))
            {
                // Verify successful - atomically delete the one-time use credential to prevent replay.
                if (await _repository.ConsumeCredentialAsync(credential.Id, cancellationToken))
                {
                    return new AuthenticationResult(PasswordVerificationResult.Success, IsCredentialConsumed: true);
                }
            }
        }
        catch (FormatException)
        {
            // Fallthrough
        }

        return new AuthenticationResult(PasswordVerificationResult.Failed);
    }
}