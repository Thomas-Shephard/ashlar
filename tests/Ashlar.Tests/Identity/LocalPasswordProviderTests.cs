using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Security.Hashing;

namespace Ashlar.Tests.Identity;

public class LocalPasswordProviderTests
{
    private FakePasswordHasher _fakeHasher;
    private PasswordHasherSelector _hasherSelector;
    private LocalPasswordProvider _provider;

    [SetUp]
    public void SetUp()
    {
        _fakeHasher = new FakePasswordHasher();
        _hasherSelector = new PasswordHasherSelector([_fakeHasher]);
        _provider = new LocalPasswordProvider(_hasherSelector);
    }

    [Test]
    public async Task AuthenticateAsyncWithValidPasswordShouldReturnSuccess()
    {
        var assertion = new LocalPasswordAssertion("password");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "user@example.com",
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };
        _fakeHasher.ShouldVerify = true;

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Success));
    }

    [Test]
    public async Task AuthenticateAsyncWithInvalidPasswordShouldReturnFailed()
    {
        var assertion = new LocalPasswordAssertion("wrong");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "user@example.com",
            CredentialValue = Convert.ToBase64String([0x01, 1, 2, 3])
        };
        _fakeHasher.ShouldVerify = false;

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithNullCredentialShouldRunHasherAndReturnFailed()
    {
        var assertion = new LocalPasswordAssertion("password");
        _fakeHasher.ShouldVerify = false;

        var result = await _provider.AuthenticateAsync(assertion, null);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithCorruptedCredentialValueShouldStillRunHasherAndReturnFailed()
    {
        var assertion = new LocalPasswordAssertion("password");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "user@example.com",
            CredentialValue = "not-base64-!"
        };
        _fakeHasher.ShouldVerify = false;

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }
}
