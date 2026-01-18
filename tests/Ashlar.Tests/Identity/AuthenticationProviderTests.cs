using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Moq;

namespace Ashlar.Tests.Identity;

public class AuthenticationProviderTests
{
    private sealed class TestProvider : IAuthenticationProvider
    {
        public ProviderType SupportedType => ProviderType.Oidc;
        public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => userId.ToString();
        public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;
        public Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, string? email, Guid? tenantId, IIdentityRepository repository, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default) => Task.FromResult(new AuthenticationResult(Ashlar.Security.Hashing.PasswordVerificationResult.Success));
    }

    [Test]
    public void DefaultProtectsCredentialsShouldBeTrue()
    {
        IAuthenticationProvider provider = new TestProvider();
        Assert.That(provider.ProtectsCredentials, Is.True);
    }

    [Test]
    public void DefaultTypicalCredentialLengthShouldBe256()
    {
        IAuthenticationProvider provider = new TestProvider();
        Assert.That(provider.TypicalCredentialLength, Is.EqualTo(256));
    }

    [Test]
    public void DefaultGetProviderNameShouldReturnSupportedTypeValue()
    {
        IAuthenticationProvider provider = new TestProvider();
        var assertionMock = new Mock<IAuthenticationAssertion>();
        Assert.That(provider.GetProviderName(assertionMock.Object), Is.EqualTo(ProviderType.Oidc.Value));
    }
}
