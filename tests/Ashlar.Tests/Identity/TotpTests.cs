using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

[TestFixture]
public class TotpTests
{
    private Mock<IIdentityRepository> _repository;
    private Mock<ICredentialService> _credentialService;
    private Mock<IAshlarTransactionProvider> _transactionProvider;
    private Mock<IAshlarTransaction> _transaction;
    private Mock<IAuthenticationRateLimiter> _rateLimiter;
    private Mock<ISecurityEventSink> _securityEvents;
    private FakeTimeProvider _timeProvider;
    private TotpOptions _options;

    [SetUp]
    public void SetUp()
    {
        _repository = new Mock<IIdentityRepository>();
        _credentialService = new Mock<ICredentialService>();
        _transactionProvider = new Mock<IAshlarTransactionProvider>();
        _transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        _rateLimiter = new Mock<IAuthenticationRateLimiter>();
        _securityEvents = new Mock<ISecurityEventSink>();
        _timeProvider = new FakeTimeProvider();
        _options = new TotpOptions();

        _transactionProvider.Setup(x => x.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_transaction.Object);
        _transaction.Setup(x => x.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()))
            .Callback<Func<CancellationToken, Task>>(onCommitted.Add);
        _transaction.Setup(x => x.CommitAsync(It.IsAny<CancellationToken>()))
            .Returns<CancellationToken>(async ct =>
            {
                foreach (var action in onCommitted)
                {
                    await action(ct);
                }
            });
    }

    private TotpService CreateService()
    {
        return new TotpService(
            _repository.Object,
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider()],
            Options.Create(_options),
            _timeProvider,
            _securityEvents.Object);
    }

    private TotpAuthenticationProvider CreateProvider()
    {
        return new TotpAuthenticationProvider(
            _rateLimiter.Object,
            Options.Create(_options),
            _timeProvider,
            _securityEvents.Object);
    }

    [Test]
    public void AddAshlarTotpRegistersServicesAndAppliesOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarTotp(options => options.CodeDigits = 8);

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<TotpOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.CodeDigits, Is.EqualTo(8));
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IAuthenticationProvider) && descriptor.ImplementationType == typeof(TotpAuthenticationProvider)), Is.True);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(ITotpService) && descriptor.ImplementationType == typeof(TotpService)), Is.True);
        }
    }

    [Test]
    public void AddAshlarTotpWithoutConfigureRegistersDefaultOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarTotp();

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<TotpOptions>>().Value;

        Assert.That(options.CodeDigits, Is.EqualTo(6));
    }

    [Test]
    public void AddAshlarTotpRegistersTotpOptionsValidation()
    {
        var services = new ServiceCollection();

        services.AddAshlarTotp(options => options.CodeDigits = 5);

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<TotpOptions>>();
        var exception = Assert.Throws<OptionsValidationException>(() => _ = options.Value);
        Assert.That(exception.Failures, Does.Contain("TOTP options are invalid."));
    }

    [Test]
    public void AddAshlarTotpIsIdempotentForProviderAndServiceRegistrations()
    {
        var services = new ServiceCollection();

        services.AddAshlarTotp();
        services.AddAshlarTotp();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(IAuthenticationProvider) && descriptor.ImplementationType == typeof(TotpAuthenticationProvider)), Has.Exactly(1).Items);
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(ITotpService) && descriptor.ImplementationType == typeof(TotpService)), Has.Exactly(1).Items);
        }
    }

    [Test]
    public void SimpleTotpRelatedModelsExposeAllProperties()
    {
        var providerKey = new AuthenticationProviderKey(ProviderType.Mfa, "custom-totp");
        var context = new AuthenticationContext(
            "user@example.com",
            Guid.NewGuid(),
            "127.0.0.1",
            "agent",
            "correlation",
            "/return",
            new Dictionary<string, string> { ["key"] = "value" },
            Guid.NewGuid());
        var attempt = new RateLimitAttempt
        {
            Key = "key",
            Purpose = "purpose",
            IpAddress = "127.0.0.1",
            UserId = "user-id",
            Email = "user@example.com",
            CorrelationId = "correlation"
        };
        var challenge = new MfaChallengeDescriptor("totp", "Authenticator app");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(new TotpAssertion("123456", ProviderKey: providerKey).ProviderIdentity, Is.EqualTo(providerKey));
            Assert.That(context.ReturnUrl, Is.EqualTo("/return"));
            Assert.That(context.Items, Contains.Key("key"));
            Assert.That(attempt.UserId, Is.EqualTo("user-id"));
            Assert.That(challenge.FactorType, Is.EqualTo("totp"));
            Assert.That(challenge.Description, Is.EqualTo("Authenticator app"));
        }

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            Guid.NewGuid(),
            "hash",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>(),
            new Dictionary<string, string> { ["factor"] = "totp" });

        Assert.That(handshake.CreatedAt, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void TotpServiceConstructorWithNullDependenciesShouldThrow()
    {
        var provider = CreateProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(null!, _credentialService.Object, _transactionProvider.Object, [provider], Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, null!, _transactionProvider.Object, [provider], Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialService.Object, null!, [provider], Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialService.Object, _transactionProvider.Object, [provider], null!));
            Assert.Throws<InvalidOperationException>(() => _ = new TotpService(_repository.Object, _credentialService.Object, _transactionProvider.Object, [], Options.Create(_options)));
        }
    }

    [Test]
    public void TotpServiceConstructorAllowsDefaultTimeProvider()
    {
        Assert.DoesNotThrow(() => _ = new TotpService(
            _repository.Object,
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider()],
            Options.Create(_options)));
    }

    [Test]
    public void Base32EncodeHandlesEmptyAndPooledBuffers()
    {
        Assert.That(Base32.Encode([]), Is.Empty);

        var bytes = Enumerable.Range(0, 128).Select(i => (byte)i).ToArray();
        var encoded = Base32.Encode(bytes);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(encoded, Has.Length.GreaterThan(128));
            Assert.That(Base32.TryDecode(encoded, out var decoded), Is.True);
            Assert.That(decoded, Is.EqualTo(bytes));
        }
    }

    [TestCase("AA", new byte[] { 0 })]
    [TestCase("aa", new byte[] { 0 })]
    [TestCase("74", new byte[] { 255 })]
    public void Base32TryDecodeHandlesValidInputs(string encoded, byte[] expected)
    {
        var result = Base32.TryDecode(encoded, out var decoded);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.True);
            Assert.That(decoded, Is.EqualTo(expected));
        }
    }

    [Test]
    public void Base32TryDecodeHandlesEmptyInputs()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Base32.TryDecode(null, out var nullResult), Is.True);
            Assert.That(nullResult, Is.Empty);
            Assert.That(Base32.TryDecode(string.Empty, out var emptyResult), Is.True);
            Assert.That(emptyResult, Is.Empty);
            Assert.That(Base32.TryDecode("====", out var paddingResult), Is.True);
            Assert.That(paddingResult, Is.Empty);
        }
    }

    [TestCase("A")]
    [TestCase("AAA")]
    [TestCase("AAAAAA")]
    [TestCase("@@")]
    [TestCase("AB")]
    public void Base32TryDecodeRejectsInvalidInputs(string encoded)
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Base32.TryDecode(encoded, out var decoded), Is.False);
            Assert.That(decoded, Is.Null);
        }
    }

    [Test]
    public void TotpAuthenticatorCoversDigitFormatsAndInvalidArguments()
    {
        byte[] key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        using (Assert.EnterMultipleScope())
        {
            Assert.That(TotpAuthenticator.GenerateCode(key, 1), Has.Length.EqualTo(6));
            Assert.That(TotpAuthenticator.GenerateCode(key, 1, 7), Has.Length.EqualTo(7));
            Assert.That(TotpAuthenticator.GenerateCode(key, 1, 8), Has.Length.EqualTo(8));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.That(TotpAuthenticator.VerifyCode(key, null!, 1), Is.False);
            Assert.That(TotpAuthenticator.VerifyCode(key, string.Empty, 1), Is.False);
            Assert.That(TotpAuthenticator.VerifyCode(key, "12345", 1), Is.False);
            Assert.That(TotpAuthenticator.VerifyCode(key, "000000", 1), Is.False);
            Assert.Throws<ArgumentOutOfRangeException>(() => TotpAuthenticator.GenerateCode(key, 1, 5));
            Assert.Throws<ArgumentOutOfRangeException>(() => TotpAuthenticator.GenerateCode(key, 1, 9));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => TotpAuthenticator.CreateOtpAuthUri("totp", "ABC", "user@example.com", null!));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => TotpAuthenticator.CreateOtpAuthUri("totp", "ABC", null!, "Ashlar"));
        }
    }

    [Test]
    public async Task StartEnrollmentAsyncGeneratesSecretAndUri()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        var enrollment = await service.StartEnrollmentAsync(userId, "Ashlar", "user@example.com");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(enrollment.SharedSecret, Is.Not.Null);
            Assert.That(enrollment.AuthenticatorUri, Does.Contain("otpauth://totp/Ashlar:user%40example.com"));
            Assert.That(enrollment.AuthenticatorUri, Does.Contain($"secret={enrollment.SharedSecret}"));
        }

        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpEnrollmentStarted &&
            d.UserId == userId), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void StartEnrollmentAsyncWithEmptyUserIdShouldThrow()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() => service.StartEnrollmentAsync(Guid.Empty, "Ashlar", "user@example.com"));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void StartEnrollmentAsyncWithInvalidIssuerShouldThrow(string? issuer)
    {
        var service = CreateService();

        Assert.That(
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.CatchAsync(() => service.StartEnrollmentAsync(Guid.NewGuid(), issuer!, "user@example.com")),
            Is.TypeOf<ArgumentException>().Or.TypeOf<ArgumentNullException>());
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void StartEnrollmentAsyncWithInvalidAccountNameShouldThrow(string? accountName)
    {
        var service = CreateService();

        Assert.That(
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.CatchAsync(() => service.StartEnrollmentAsync(Guid.NewGuid(), "Ashlar", accountName!)),
            Is.TypeOf<ArgumentException>().Or.TypeOf<ArgumentNullException>());
    }

    [Test]
    public async Task VerifyAndEnrollAsyncSucceedsWithCorrectCode()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _repository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        var result = await service.VerifyAndEnrollAsync(userId, secret, code);

        Assert.That(result, Is.True);
        _credentialService.Verify(x => x.LinkCredentialAsync(userId, It.IsAny<TotpAssertion>(), It.IsAny<IAuthenticationProvider>(), secret, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()), Times.Once);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpEnrollmentCompleted), It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task VerifyAndEnrollAsyncReplacesExistingCredential()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _repository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        var result = await service.VerifyAndEnrollAsync(userId, secret, code);

        Assert.That(result, Is.True);
        _repository.Verify(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task VerifyAndEnrollAsyncFailsWithIncorrectCode()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);

        var result = await service.VerifyAndEnrollAsync(userId, secret, "000000");

        Assert.That(result, Is.False);
        _credentialService.Verify(x => x.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task VerifyAndEnrollAsyncFailsWithEmptyCode()
    {
        var service = CreateService();
        var result = await service.VerifyAndEnrollAsync(Guid.NewGuid(), "secret", "");
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task VerifyAndEnrollAsyncFailsWithInvalidSecret()
    {
        var service = CreateService();
        var result = await service.VerifyAndEnrollAsync(Guid.NewGuid(), "invalid-base32!", "123456");
        Assert.That(result, Is.False);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public async Task VerifyAndEnrollAsyncFailsWithMissingSharedSecret(string? sharedSecret)
    {
        var service = CreateService();

        // ReSharper disable once NullableWarningSuppressionIsUsed
        var result = await service.VerifyAndEnrollAsync(Guid.NewGuid(), sharedSecret!, "123456");

        Assert.That(result, Is.False);
    }

    [Test]
    public async Task VerifyAndEnrollAsyncFailsWithTooLongSharedSecret()
    {
        var service = CreateService();
        var sharedSecret = new string('A', 257);

        var result = await service.VerifyAndEnrollAsync(Guid.NewGuid(), sharedSecret, "123456");

        Assert.That(result, Is.False);
    }

    [Test]
    public void VerifyAndEnrollAsyncWithEmptyUserIdShouldThrow()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() => service.VerifyAndEnrollAsync(Guid.Empty, "secret", "123456"));
    }

    [Test]
    public async Task DisableTotpAsyncSucceedsWhenCredentialExists()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        _repository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        var result = await service.DisableTotpAsync(userId);

        Assert.That(result, Is.True);
        _repository.Verify(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()), Times.Once);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpDisabled), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task DisableTotpAsyncFailsWhenNoCredentialExists()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        _repository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        var result = await service.DisableTotpAsync(userId);

        Assert.That(result, Is.False);
    }

    [Test]
    public void DisableTotpAsyncWithEmptyUserIdShouldThrow()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() => service.DisableTotpAsync(Guid.Empty));
    }

    [TestCase(0, 6, 30, 1)]
    [TestCase(20, 5, 30, 1)]
    [TestCase(20, 9, 30, 1)]
    [TestCase(20, 6, 0, 1)]
    [TestCase(20, 6, 30, -1)]
    public void ProviderWithInvalidTotpOptionsShouldThrow(int secretLengthBytes, int codeDigits, int stepSeconds, int allowedSkewSteps)
    {
        _options.SecretLengthBytes = secretLengthBytes;
        _options.CodeDigits = codeDigits;
        _options.StepSeconds = stepSeconds;
        _options.AllowedSkewSteps = allowedSkewSteps;

        Assert.Throws<ArgumentException>(() => CreateProvider());
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ProviderConstructorWithNullDependenciesShouldThrow()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new TotpAuthenticationProvider(null!, Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpAuthenticationProvider(_rateLimiter.Object, null!));
        }
    }

    [Test]
    public void ProviderConstructorAllowsDefaultTimeProvider()
    {
        Assert.DoesNotThrow(() => _ = new TotpAuthenticationProvider(_rateLimiter.Object, Options.Create(_options)));
    }

    [Test]
    public void ProviderSimpleMembersReturnExpectedValues()
    {
        var provider = CreateProvider();
        var assertion = new TotpAssertion("123456");
        var userId = Guid.NewGuid();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.ProtectsCredentials, Is.True);
            Assert.That(provider.TypicalCredentialLength, Is.EqualTo(32));
            Assert.That(provider.GetProviderKey(assertion, userId), Is.EqualTo(userId.ToString("D")));
            Assert.That(provider.PrepareCredentialValue(assertion, "secret"), Is.EqualTo("secret"));
        }
    }

    [Test]
    public async Task ProviderAuthenticateAsyncSucceedsWithCorrectCode()
    {
        var provider = CreateProvider();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = _options.ProviderKey.Type,
            ProviderName = _options.ProviderKey.Name,
            ProviderKey = "test",
            CredentialValue = secret,
            Status = CredentialStatus.Active,
            CreatedAt = DateTimeOffset.UtcNow,
            Version = "1"
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion(code), credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
            Assert.That(result.NewMetadata, Is.Not.Null);
            Assert.That(result.CredentialUpdateRequirement, Is.EqualTo(CredentialUpdateRequirement.Required));
        }
    }

    [Test]
    public async Task ProviderAuthenticateAsyncFailsOnReplay()
    {
        var provider = CreateProvider();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var step = _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30;
        var code = TotpAuthenticator.GenerateCode(secretBytes, step);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = _options.ProviderKey.Type,
            ProviderName = _options.ProviderKey.Name,
            ProviderKey = "test",
            CredentialValue = secret,
            Status = CredentialStatus.Active,
            CreatedAt = DateTimeOffset.UtcNow,
            Version = "1",
            Metadata = $"{{\"LastUsedStep\":{step}}}"
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion(code), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [TestCase("null")]
    [TestCase("{")]
    public async Task ProviderAuthenticateAsyncSucceedsWithNullOrMalformedMetadata(string metadata)
    {
        var provider = CreateProvider();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var step = _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30;
        var code = TotpAuthenticator.GenerateCode(secretBytes, step);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = _options.ProviderKey.Type,
            ProviderName = _options.ProviderKey.Name,
            ProviderKey = "test",
            CredentialValue = secret,
            Status = CredentialStatus.Active,
            CreatedAt = DateTimeOffset.UtcNow,
            Version = "1",
            Metadata = metadata
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion(code), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
    }

    [Test]
    public async Task ProviderAuthenticateAsyncReturnsFailedOnNullCredential()
    {
        var provider = CreateProvider();

        var result = await provider.AuthenticateAsync(new TotpAssertion("123456"), null);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task ProviderAuthenticateAsyncFailsWithIncorrectCode()
    {
        var provider = CreateProvider();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = _options.ProviderKey.Type,
            ProviderName = _options.ProviderKey.Name,
            ProviderKey = "test",
            CredentialValue = secret,
            Status = CredentialStatus.Active,
            CreatedAt = DateTimeOffset.UtcNow,
            Version = "1"
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion("000000"), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task ProviderAuthenticateAsyncFailsWithInvalidSecret()
    {
        var provider = CreateProvider();
        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = _options.ProviderKey.Type,
            ProviderName = _options.ProviderKey.Name,
            ProviderKey = "test",
            CredentialValue = "invalid-base32!",
            Status = CredentialStatus.Active,
            CreatedAt = DateTimeOffset.UtcNow,
            Version = "1"
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion("123456"), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncRateLimits()
    {
        var provider = CreateProvider();
        var userId = Guid.NewGuid();
        var assertion = new TotpAssertion("123456");

        _rateLimiter.Setup(x => x.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Blocked, Remaining = 0, WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(5) });

        var result = await provider.ResolveCredentialAsync(userId, assertion, _repository.Object);

        Assert.That(result, Is.Null);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpVerificationRateLimited), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullOnWrongAssertion()
    {
        var provider = CreateProvider();
        _rateLimiter.Setup(x => x.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(5) });

        var result = await provider.ResolveCredentialAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, _repository.Object);
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsCredential()
    {
        var provider = CreateProvider();
        var userId = Guid.NewGuid();
        var assertion = new TotpAssertion("123456");
        var credential = new UserCredential { Id = Guid.NewGuid(), UserId = userId, ProviderType = _options.ProviderKey.Type, ProviderName = _options.ProviderKey.Name, ProviderKey = userId.ToString("D"), Status = CredentialStatus.Active, CreatedAt = DateTimeOffset.UtcNow, Version = "1" };

        _rateLimiter.Setup(x => x.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(5) });
        _repository.Setup(x => x.GetCredentialForUserAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, userId.ToString("D"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var result = await provider.ResolveCredentialAsync(userId, assertion, _repository.Object);

        Assert.That(result, Is.SameAs(credential));
    }

    [Test]
    public void ProviderAuthenticateAsyncThrowsOnWrongAssertionType()
    {
        var provider = CreateProvider();
        var credential = new UserCredential { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), ProviderType = ProviderType.Mfa, ProviderName = "totp", ProviderKey = "test", Status = CredentialStatus.Active, CreatedAt = DateTimeOffset.UtcNow, Version = "1" };

        Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateAsync(new Mock<IAuthenticationAssertion>().Object, credential));
    }

    [Test]
    public async Task ProviderAuthenticateAsyncReturnsFailedOnNullCredentialValue()
    {
        var provider = CreateProvider();
        var credential = new UserCredential { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), ProviderType = ProviderType.Mfa, ProviderName = "totp", ProviderKey = "test", Status = CredentialStatus.Active, CreatedAt = DateTimeOffset.UtcNow, Version = "1", CredentialValue = null };

        var result = await provider.AuthenticateAsync(new TotpAssertion("123456"), credential);
        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsNull()
    {
        var provider = CreateProvider();
        var result = await provider.FindUserAsync(new TotpAssertion("123456"), new AuthenticationContext("user@example.com", Guid.NewGuid(), "127.0.0.1"), _repository.Object);
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task OrchestratorIntegrationTest()
    {
        // This test proves that the orchestrator uses the pipeline (and thus our provider) for verification.
        var pipeline = new Mock<IAuthenticationPipeline>();
        var handshakeService = new Mock<IAuthenticationHandshakeService>();
        var policyEvaluator = new Mock<IMfaPolicyEvaluator>();
        var orchestrator = new AuthenticationOrchestrator(pipeline.Object, handshakeService.Object, policyEvaluator.Object);

        var userId = Guid.NewGuid();
        var handshakeToken = "handshake-token";
        var handshake = new AuthenticationHandshake(
            Id: Guid.NewGuid(),
            UserId: userId,
            TokenHash: "hash",
            CreatedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddMinutes(5),
            IsRevoked: false,
            IsCompleted: false,
            RequiredFactors: new HashSet<string> { "totp" },
            VerifiedFactors: new HashSet<string>());

        handshakeService.Setup(x => x.GetHandshakeAsync(handshakeToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(handshake);

        var assertion = new TotpAssertion("123456");
        var context = new AuthenticationContext();

        var responseUser = new Mock<IUser>();
        responseUser.Setup(u => u.Id).Returns(userId);
        pipeline.Setup(x => x.LoginAsync(It.Is<AuthenticationContext>(c => c.UserId == userId), assertion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, responseUser.Object, AuthenticationStatus.Success));

        handshakeService.Setup(x => x.VerifyFactorAsync(It.IsAny<VerifyAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationHandshakeResult(true, handshake));

        var result = await orchestrator.VerifyFactorAsync(handshakeToken, "totp", context, assertion);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
        pipeline.Verify(x => x.LoginAsync(It.Is<AuthenticationContext>(c => c.UserId == userId), assertion, It.IsAny<CancellationToken>()), Times.Once);
    }
}
