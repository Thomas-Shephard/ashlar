using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
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
        var assertion = new LocalPasswordAssertion("pass");
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };

        var key = _provider.GetProviderKey(assertion, user.Id);

        Assert.That(key, Is.EqualTo(user.Id.ToString("D")));
    }

    [Test]
    public void GetProviderKeyWithNullAssertionShouldThrow()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _provider.GetProviderKey(null!, Guid.NewGuid()));
    }

    [Test]
    public void GetProviderNameShouldReturnLocal()
    {
        var assertion = new LocalPasswordAssertion("pass");
        var name = ((IAuthenticationProvider)_provider).GetProviderName(assertion);
        Assert.That(name, Is.EqualTo(ProviderType.Local.Value));
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

    [Test]
    public Task FindUserAsyncWithNullRepositoryShouldThrow()
    {
        var assertion = new LocalPasswordAssertion("pass");
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.ThrowsAsync<ArgumentNullException>(() => _provider.FindUserAsync(assertion, "test@example.com", null, null!));
        return Task.CompletedTask;
    }

    [Test]
    public async Task FindUserAsyncWithWrongAssertionTypeShouldReturnNull()
    {
        var assertion = new Mock<IAuthenticationAssertion>().Object;
        var result = await _provider.FindUserAsync(assertion, "test@example.com", null, new Mock<IIdentityRepository>().Object);
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task FindUserAsyncWithEmptyEmailShouldReturnNull()
    {
        var assertion = new LocalPasswordAssertion("pass");
        var result = await _provider.FindUserAsync(assertion, "", null, new Mock<IIdentityRepository>().Object);
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task FindUserAsyncShouldCallRepository()
    {
        var assertion = new LocalPasswordAssertion("pass");
        var email = "test@example.com";
        var tenantId = Guid.NewGuid();
        var user = new User { Id = Guid.NewGuid(), Email = email };
        var repoMock = new Mock<IIdentityRepository>();
        repoMock.Setup(r => r.GetUserByEmailAsync(email, tenantId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _provider.FindUserAsync(assertion, email, tenantId, repoMock.Object);

        Assert.That(result, Is.EqualTo(user));
    }
}
