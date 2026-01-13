using Ashlar.Identity.Models;
using Ashlar.Security.Hashing;

namespace Ashlar.Identity.Abstractions;

public interface IAuthenticationProvider
{
    ProviderType SupportedType { get; }

    bool IsPrimary => false;
    bool IsSecondary => false;
    bool BypassesMfa(IAuthenticationAssertion assertion) => false;
    bool ProtectsCredentials => true;

    string GetProviderName(IAuthenticationAssertion assertion) => SupportedType.Value;
    string? GetProviderKey(IAuthenticationAssertion assertion, IUser user);
    string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue);
    Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default);
}

public sealed record AuthenticationResult(
    PasswordVerificationResult Result,
    IDictionary<string, string>? Claims = null,
    bool ShouldUpdateCredential = false,
    string? NewCredentialValue = null,
    string? NewMetadata = null,
    bool IsCredentialConsumed = false);
