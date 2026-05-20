namespace Ashlar.Tests.Identity.Features.Authentication;

internal sealed class AuthenticationProviderTests
{
    private sealed class TestProvider : IAuthenticationProvider
    {
        public AuthenticationProviderKey Key => new(ProviderType.Oidc, "Google");
        public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => userId.ToString();
        public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;
        public Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default) => Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Succeeded));
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

}
