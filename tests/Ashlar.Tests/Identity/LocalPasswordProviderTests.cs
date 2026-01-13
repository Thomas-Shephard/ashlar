using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Providers;
using Ashlar.Identity.Providers.Local;
using Ashlar.Security.Hashing;
using Moq;

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
    public void ConstructorWithNullHasherSelectorShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new LocalPasswordProvider(null!));
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

    [Test]
    public async Task AuthenticateAsyncWithNullCredentialValueShouldReturnFailed()
    {
        var assertion = new LocalPasswordAssertion("password");
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.Local,
            ProviderName = "Local",
            ProviderKey = "user@example.com",
            CredentialValue = null
        };
        _fakeHasher.ShouldVerify = false;

        var result = await _provider.AuthenticateAsync(assertion, credential);

        Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.Failed));
    }

    [Test]
    public async Task AuthenticateAsyncWithRehashNeededShouldReturnSuccessRehashNeeded()
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

        var oldHasher = new FakePasswordHasher { Version = 0x01, ShouldVerify = true };
        var newHasher = new FakePasswordHasher { Version = 0x02 };
        var selector = new PasswordHasherSelector([oldHasher, newHasher]);
        var provider = new LocalPasswordProvider(selector);

        var result = await provider.AuthenticateAsync(assertion, credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Result, Is.EqualTo(PasswordVerificationResult.SuccessRehashNeeded));
            Assert.That(result.ShouldUpdateCredential, Is.True);
            Assert.That(result.NewCredentialValue, Is.Not.Null);
        }
    }

    [Test]
    public void GetProviderKeyShouldReturnUserId()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com" };
        var assertion = new LocalPasswordAssertion("pass");

        var key = _provider.GetProviderKey(assertion, user);

        Assert.That(key, Is.EqualTo(userId.ToString("D")));
    }

    [Test]
    public void PrepareCredentialValueShouldHashPassword()
    {
        var password = "password123";
        var assertion = new LocalPasswordAssertion(password);
        var expectedHash = Convert.ToBase64String(new byte[] { 0x01, 0, 0, 0 }); // Version 0x01 from FakePasswordHasher

        var result = _provider.PrepareCredentialValue(assertion, password);

        Assert.That(result, Is.EqualTo(expectedHash));
    }

    [Test]
    public void PrepareCredentialValueWithNullShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _provider.PrepareCredentialValue(new LocalPasswordAssertion("p"), null!));
    }

    [Test]
    public void PrepareCredentialValueWithEmptyShouldThrow()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => _provider.PrepareCredentialValue(new LocalPasswordAssertion("p"), ""));
            Assert.Throws<ArgumentException>(() => _provider.PrepareCredentialValue(new LocalPasswordAssertion("p"), " "));
        }
    }

    [Test]
    public void AuthenticateAsyncWithWrongAssertionTypeShouldThrow()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        Assert.ThrowsAsync<ArgumentException>(() => _provider.AuthenticateAsync(assertion, null));
    }
}
