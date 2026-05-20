using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.Identity.Features.Mfa;

[TestFixture]
internal sealed class RecoveryCodeTests
{
    [Test]
    public void GeneratorGeneratesUniqueCodes()
    {
        var codes = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            var code = RecoveryCodeGenerator.GenerateCode(12, 4);
            using (Assert.EnterMultipleScope())
            {
                Assert.That(codes.Add(code), Is.True, "Generated non-unique code");
                Assert.That(code, Has.Length.EqualTo(14)); // 12 chars + 2 dashes
            }
            using (Assert.EnterMultipleScope())
            {
                Assert.That(code[4], Is.EqualTo('-'));
                Assert.That(code[9], Is.EqualTo('-'));
            }
        }
    }

    [Test]
    public void GeneratorThrowsOnInvalidInput()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => RecoveryCodeGenerator.GenerateCode(0, 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => RecoveryCodeGenerator.GenerateCode(12, 0));
    }

    [Test]
    public void AssertionConstructorSetsProperties()
    {
        var code = "TEST-CODE";
        var providerIdentity = new AuthenticationProviderKey(ProviderType.RecoveryCode, "Custom");

        var assertion1 = new RecoveryCodeAssertion(code);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion1.Code, Is.EqualTo(code));
            Assert.That(assertion1.ProviderIdentity.Name, Is.EqualTo("RecoveryCode"));
        }

        var assertion2 = new RecoveryCodeAssertion(code, providerIdentity);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion2.ProviderIdentity, Is.EqualTo(providerIdentity));
        }
    }

    [Test]
    public void AssertionConstructorThrowsOnInvalidCode()
    {
        Assert.Throws<ArgumentException>(() => _ = new RecoveryCodeAssertion(" "));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ServiceConstructorThrowsOnNull()
    {
        var repo = new Mock<IIdentityRepository>().Object;
        var trans = new Mock<IAshlarTransactionProvider>().Object;
        var hasher = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());

        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(null!, trans, hasher, options));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, null!, hasher, options));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, trans, null!, options));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, trans, hasher, null!));

        var optionsMock = new Mock<IOptions<RecoveryCodeOptions>>();
        optionsMock.SetupGet(o => o.Value).Returns((RecoveryCodeOptions)null!);
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, trans, hasher, optionsMock.Object));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncReturnsExpectedCount()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 5, ExpiresAfter = TimeSpan.FromDays(1) });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com", IsActive = true });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);

        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options);

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest { Audit = new AuditContext(IpAddress: "203.0.113.51") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Has.Count.EqualTo(5));
        }
        repository.Verify(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()), Times.Once);
        repository.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c => c.Purpose == "recovery-code" && c.ExpiresAt != null), It.IsAny<CancellationToken>()), Times.Exactly(5));
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncWithRequestOverridesOptions()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 5 });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com", IsActive = true });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);

        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options);

        var request = new RecoveryCodeGenerationRequest { CodeCount = 3, ReplaceExisting = false, ExpiresAfter = TimeSpan.FromHours(1) };
        var result = await service.GenerateRecoveryCodesAsync(userId, request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Has.Count.EqualTo(3));
        }
        repository.Verify(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()), Times.Never);
        repository.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c => c.ExpiresAt != null), It.IsAny<CancellationToken>()), Times.Exactly(3));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncPropagatesAuditToEventAndNotification()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var securityEvents = new Mock<ISecurityEventSink>();
        var notificationService = new Mock<ISecurityNotificationService>();
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();
        var audit = new AuditContext(ActorUserId: userId, IpAddress: "203.0.113.50", UserAgent: "recovery-agent", CorrelationId: "recovery-correlation");

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com", IsActive = true });
        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);
        transaction.Setup(t => t.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()))
            .Callback<Func<CancellationToken, Task>>(onCommitted.Add);
        transaction.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>()))
            .Returns<CancellationToken>(async ct =>
            {
                foreach (var action in onCommitted)
                {
                    await action(ct);
                }
            });
        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options, securityEventSink: securityEvents.Object, notificationService: notificationService.Object);

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest { Audit = audit });

        Assert.That(result.Succeeded, Is.True);
        securityEvents.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.RecoveryCodesGenerated &&
            e.ActorUserId == userId &&
            e.IpAddress == "203.0.113.50" &&
            e.UserAgent == "recovery-agent" &&
            e.CorrelationId == "recovery-correlation"), It.IsAny<CancellationToken>()), Times.Once);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.RecoveryCodesGenerated &&
            notification.IpAddress == "203.0.113.50" &&
            notification.UserAgent == "recovery-agent"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncNotifiesWithoutAuditContext()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var notificationService = new Mock<ISecurityNotificationService>();
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com", IsActive = true });
        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);
        transaction.Setup(t => t.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()))
            .Callback<Func<CancellationToken, Task>>(onCommitted.Add);
        transaction.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>()))
            .Returns<CancellationToken>(async ct =>
            {
                foreach (var action in onCommitted)
                {
                    await action(ct);
                }
            });
        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options, notificationService: notificationService.Object);

        var result = await service.GenerateRecoveryCodesAsync(userId);

        Assert.That(result.Succeeded, Is.True);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.RecoveryCodesGenerated &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncWithNoExpiryCreatesNonExpiringCredentials()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 1, ExpiresAfter = null });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, Email = "test@example.com", IsActive = true });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);

        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options);

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest { Audit = new AuditContext(IpAddress: "203.0.113.51") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Has.Count.EqualTo(1));
        }
        repository.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c => c.ExpiresAt == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void ServiceGenerateRecoveryCodesAsyncThrowsOnInvalidUserId()
    {
        var service = new RecoveryCodeService(new Mock<IIdentityRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        Assert.That(async () => await service.GenerateRecoveryCodesAsync(Guid.Empty), Throws.ArgumentException);
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncFailsIfUserNotFound()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Mock<IAshlarTransaction>().Object);

        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options);

        var result = await service.GenerateRecoveryCodesAsync(userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncFailsOnInvalidGenerationRequest()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 5 });
        var audit = new AuditContext(IpAddress: "203.0.113.52");
        var tooMany = new RecoveryCodeGenerationRequest { CodeCount = 11, Audit = audit };
        var zero = new RecoveryCodeGenerationRequest { CodeCount = 0, Audit = audit };
        var negativeExpiry = new RecoveryCodeGenerationRequest { CodeCount = 1, ExpiresAfter = TimeSpan.Zero, Audit = audit };

        var tooManyResult = await service.GenerateRecoveryCodesAsync(Guid.NewGuid(), tooMany);
        var zeroResult = await service.GenerateRecoveryCodesAsync(Guid.NewGuid(), zero);
        var negativeExpiryResult = await service.GenerateRecoveryCodesAsync(Guid.NewGuid(), negativeExpiry);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tooManyResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCodeCount));
            Assert.That(zeroResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCodeCount));
            Assert.That(negativeExpiryResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidExpiry));
        }
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncFailsOnInvalidOptions()
    {
        var invalidCodeLength = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeLength = 0 });
        var invalidGroupSize = CreateServiceForGenerationValidation(new RecoveryCodeOptions { GroupSize = 0 });

        var request = new RecoveryCodeGenerationRequest { Audit = new AuditContext(IpAddress: "203.0.113.53") };
        var invalidCodeLengthResult = await invalidCodeLength.GenerateRecoveryCodesAsync(Guid.NewGuid(), request);
        var invalidGroupSizeResult = await invalidGroupSize.GenerateRecoveryCodesAsync(Guid.NewGuid(), request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invalidCodeLengthResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidConfiguration));
            Assert.That(invalidGroupSizeResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidConfiguration));
        }
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncCoversDefaultInvalidGenerationPaths()
    {
        var missingUser = new RecoveryCodeService(
            Mock.Of<IIdentityRepository>(),
            Mock.Of<IAshlarTransactionProvider>(provider => provider.BeginTransactionAsync(It.IsAny<CancellationToken>()) == Task.FromResult(Mock.Of<IAshlarTransaction>())),
            new PasswordHasherSelector([new PasswordHasherV1()]),
            Options.Create(new RecoveryCodeOptions()));
        var invalidCount = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 0 });
        var invalidConfiguration = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeLength = 0 });
        var invalidExpiry = CreateServiceForGenerationValidation(new RecoveryCodeOptions { ExpiresAfter = TimeSpan.Zero });

        var missingUserResult = await missingUser.GenerateRecoveryCodesAsync(Guid.NewGuid());
        var invalidCountResult = await invalidCount.GenerateRecoveryCodesAsync(Guid.NewGuid());
        var invalidConfigurationResult = await invalidConfiguration.GenerateRecoveryCodesAsync(Guid.NewGuid());
        var invalidExpiryResult = await invalidExpiry.GenerateRecoveryCodesAsync(Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingUserResult.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(invalidCountResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCodeCount));
            Assert.That(invalidConfigurationResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidConfiguration));
            Assert.That(invalidExpiryResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidExpiry));
        }
    }

    [Test]
    public async Task ServiceRevokeRecoveryCodesAsyncSucceeds()
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();

        repository.Setup(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()))
            .ReturnsAsync(10);

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);
        transaction.Setup(t => t.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()))
            .Callback<Func<CancellationToken, Task>>(onCommitted.Add);
        transaction.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>()))
            .Returns<CancellationToken>(async ct =>
            {
                foreach (var action in onCommitted)
                {
                    await action(ct);
                }

                onCommitted.Clear();
            });

        var service = new RecoveryCodeService(repository.Object, transactionProvider.Object, hasherSelector, options);

        var result1 = await service.RevokeRecoveryCodesAsync(userId, "test reason");
        Assert.That(result1, Is.EqualTo(10));

        var result2 = await service.RevokeRecoveryCodesAsync(userId);
        Assert.That(result2, Is.EqualTo(10));

        repository.Verify(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()), Times.Exactly(2));
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Test]
    public void ServiceRevokeRecoveryCodesAsyncThrowsOnInvalidUserId()
    {
        var service = new RecoveryCodeService(new Mock<IIdentityRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        Assert.That(async () => await service.RevokeRecoveryCodesAsync(Guid.Empty), Throws.ArgumentException);
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ProviderConstructorThrowsOnNull()
    {
        var hasher = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>().Object;
        var options = Options.Create(new RecoveryCodeOptions());

        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(null!, rateLimiter, options));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(hasher, null!, options));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(hasher, rateLimiter, null!));

        var optionsMock = new Mock<IOptions<RecoveryCodeOptions>>();
        optionsMock.SetupGet(o => o.Value).Returns((RecoveryCodeOptions)null!);
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(hasher, rateLimiter, optionsMock.Object));
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsMatchedCredential()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var options = Options.Create(new RecoveryCodeOptions());
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "code1";
        var secretCode = "ABCD-EFGH-IJKL";
        var rawCode = $"{providerKey}-{secretCode}";
        var hashedCode = Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(secretCode));

        var credentials = new List<UserCredential>
        {
            CreateCredential(userId, hashedCode, providerKey),
            CreateCredential(userId, "some-other-hash", "code2")
        };

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = DateTimeOffset.UtcNow });

        repository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credentials[0]);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, options);
        var assertion = new RecoveryCodeAssertion(rawCode);
        var context = new AuthenticationContext(IpAddress: "1.2.3.4");

        var result = await provider.ResolveCredentialAsync(userId, assertion, context, repository.Object);

        Assert.That(result, Is.Not.Null);
        Assert.That(result.ProviderKey, Is.EqualTo(providerKey));
        rateLimiter.Verify(r => r.CheckAsync(It.Is<RateLimitAttempt>(a => a.IpAddress == "1.2.3.4"), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfNoMatch()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var options = Options.Create(new RecoveryCodeOptions());
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "code1";
        var secretCode = "WRONG-CODE";
        var rawCode = $"{providerKey}-{secretCode}";

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = DateTimeOffset.UtcNow });

        repository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateCredential(userId, "bad-hash", providerKey));

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await provider.ResolveCredentialAsync(userId, assertion, null, repository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfCredentialIsMissing()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var options = Options.Create(new RecoveryCodeOptions());
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();
        var rawCode = "code1-ABCD-EFGH-IJKL";

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = DateTimeOffset.UtcNow });

        repository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await provider.ResolveCredentialAsync(userId, assertion, null, repository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfExpired()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var options = Options.Create(new RecoveryCodeOptions());
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "code1";
        var secretCode = "ABCD-EFGH-IJKL";
        var rawCode = $"{providerKey}-{secretCode}";
        var hashedCode = Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(secretCode));

        var expired = CreateCredential(userId, hashedCode, providerKey);
        expired.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = DateTimeOffset.UtcNow });

        repository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(expired);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await provider.ResolveCredentialAsync(userId, assertion, null, repository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfRateLimited()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var options = Options.Create(new RecoveryCodeOptions());
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Blocked, Remaining = 0, WindowResetAt = DateTimeOffset.UtcNow });

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, options);
        var assertion = new RecoveryCodeAssertion("SOME-CODE");

        var result = await provider.ResolveCredentialAsync(userId, assertion, null, repository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullForUnsupportedAssertion()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));

        var result = await provider.ResolveCredentialAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, null, new Mock<IIdentityRepository>().Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullForMalformedCode()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, Options.Create(new RecoveryCodeOptions()));

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = DateTimeOffset.UtcNow });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await provider.ResolveCredentialAsync(Guid.NewGuid(), new RecoveryCodeAssertion("CODE"), null, new Mock<IIdentityRepository>().Object), Is.Null);
            Assert.That(await provider.ResolveCredentialAsync(Guid.NewGuid(), new RecoveryCodeAssertion("CODE-"), null, new Mock<IIdentityRepository>().Object), Is.Null);
        }
    }

    [Test]
    public async Task ProviderAuthenticateAsyncSucceedsIfCredentialNotNull()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        var assertion = new RecoveryCodeAssertion("SOME-CODE");
        var credential = CreateCredential(Guid.NewGuid(), "hash", "key");

        var result = await provider.AuthenticateAsync(assertion, credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Succeeded));
            Assert.That(result.IsCredentialConsumed, Is.True);
        }
    }

    [Test]
    public async Task ProviderAuthenticateAsyncFailsIfCredentialNull()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        var assertion = new RecoveryCodeAssertion("SOME-CODE");

        var result = await provider.AuthenticateAsync(assertion, null);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public void DiRegistrationResolvesServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IIdentityRepository>().Object);
        services.AddSingleton(new Mock<IAshlarTransactionProvider>().Object);
        services.AddAshlarRecoveryCodes(opts =>
        {
            opts.CodeCount = 12;
        });

        var provider = services.BuildServiceProvider();

        Assert.That(provider.GetService<IRecoveryCodeService>(), Is.Not.Null);
        var authProviders = provider.GetServices<IAuthenticationProvider>();
        Assert.That(authProviders.Any(p => p is RecoveryCodeAuthenticationProvider), Is.True);

        var options = provider.GetRequiredService<IOptions<RecoveryCodeOptions>>().Value;
        Assert.That(options.CodeCount, Is.EqualTo(12));
    }

    [Test]
    public void ProviderTypicalCredentialLengthIsExpected()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.TypicalCredentialLength, Is.EqualTo(128));
            Assert.That(provider.ProtectsCredentials, Is.False);
        }
    }

    [Test]
    public void ProviderGetProviderKeyReturnsEmpty()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion("CODE"), Guid.NewGuid()), Is.Empty);
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion("CODE"), Guid.NewGuid()), Is.Empty);
        }
    }

    [Test]
    public void ProviderPrepareCredentialValueReturnsHashedValue()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        var assertion = new RecoveryCodeAssertion("SOME-CODE");

        var prepared = provider.PrepareCredentialValue(assertion, "RAW-VALUE");

        Assert.That(prepared, Is.Not.Null);
        Assert.That(prepared, Is.Not.EqualTo("RAW-VALUE"));
    }

    [Test]
    public void ProviderPrepareCredentialValueReturnsNullIfEmpty()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.PrepareCredentialValue(new RecoveryCodeAssertion("CODE"), " "), Is.Null);
            Assert.That(provider.PrepareCredentialValue(new RecoveryCodeAssertion("CODE"), null), Is.Null);
        }
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsUserByEmail()
    {
        var repository = new Mock<IIdentityRepository>();
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        var context = new AuthenticationContext(Email: "test@example.com");
        var user = new User { Id = Guid.NewGuid(), Email = "test@example.com" };

        repository.Setup(r => r.GetUserByEmailAsync("test@example.com", It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var found = await provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), context, repository.Object);

        Assert.That(found, Is.Not.Null);
        Assert.That(found.Id, Is.EqualTo(user.Id));
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsUserByUserId()
    {
        var repository = new Mock<IIdentityRepository>();
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext(UserId: userId);
        var user = new User { Id = userId, Email = "test@example.com" };

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var found = await provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), context, repository.Object);

        Assert.That(found, Is.Not.Null);
        Assert.That(found.Id, Is.EqualTo(userId));
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncResilientToWhitespaceAndCasing()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var rateLimiter = new Mock<IAuthenticationRateLimiter>();
        var options = Options.Create(new RecoveryCodeOptions());
        var repository = new Mock<IIdentityRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "CODE1";
        var secretCode = "ABCD-EFGH-IJKL";
        var rawCode = "  code 1 - abcd - efgh - ijkl  "; // Mixed casing and spaces
        var hashedCode = Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(secretCode));

        rateLimiter.Setup(r => r.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision { Status = RateLimitStatus.Allowed, Remaining = 5, WindowResetAt = DateTimeOffset.UtcNow });

        repository.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateCredential(userId, hashedCode, providerKey));

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, rateLimiter.Object, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await provider.ResolveCredentialAsync(userId, assertion, null, repository.Object);

        Assert.That(result, Is.Not.Null);
        Assert.That(result.ProviderKey, Is.EqualTo(providerKey));
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsNullOnWrongConditions()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));

        using (Assert.EnterMultipleScope())
        {
            // Wrong assertion
            Assert.That(await provider.FindUserAsync(new Mock<IAuthenticationAssertion>().Object, new AuthenticationContext(Email: "test@example.com"), new Mock<IIdentityRepository>().Object), Is.Null);

            // Missing email (empty, whitespace, and null)
            Assert.That(await provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(Email: ""), new Mock<IIdentityRepository>().Object), Is.Null);
            Assert.That(await provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(Email: " "), new Mock<IIdentityRepository>().Object), Is.Null);
            Assert.That(await provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(Email: null), new Mock<IIdentityRepository>().Object), Is.Null);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ProviderFindUserAsyncThrowsOnNullArguments()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        Assert.ThrowsAsync<ArgumentNullException>(() => provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), null!, new Mock<IIdentityRepository>().Object));
        Assert.ThrowsAsync<ArgumentNullException>(() => provider.FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(), null!));
    }

    [Test]
    public void ProviderAuthenticateAsyncThrowsOnWrongAssertionType()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), new Mock<IAuthenticationRateLimiter>().Object, Options.Create(new RecoveryCodeOptions()));
        Assert.That(async () => await provider.AuthenticateAsync(new Mock<IAuthenticationAssertion>().Object, null), Throws.ArgumentException);
    }

    [Test]
    public async Task AuthenticationProviderDefaultResolveCredentialAsyncReturnsNull()
    {
        IAuthenticationProvider provider = new DefaultResolveCredentialProvider();

        var result = await provider.ResolveCredentialAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, null, new Mock<IIdentityRepository>().Object);

        Assert.That(result, Is.Null);
    }


    [Test]
    public async Task PipelineHandlesInconsistentCredentialState()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new Mock<ICredentialService>();
        var transProvider = new Mock<IAshlarTransactionProvider>();
        var securityEventSink = new Mock<ISecurityEventSink>();

        var userId = Guid.NewGuid();
        var user = new User { Id = userId, Email = "test@example.com", IsActive = true };
        var assertion = new RecoveryCodeAssertion("CODE");
        var context = new AuthenticationContext(Email: "test@example.com");

        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode"));

        IAuthenticationProvider? providerObj = provider.Object;
        providerRegistry.Setup(r => r.TryGetProvider(assertion, out providerObj)).Returns(true);

        // Setup: ResolveAsync returns NULL credential
        credentialService.Setup(s => s.ResolveAsync(context, assertion, provider.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, null, null, false));

        // Setup: AuthenticateAsync returns SUCCESS but requests consumption
        provider.Setup(p => p.AuthenticateAsync(assertion, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));

        var pipeline = new AuthenticationPipeline(providerRegistry.Object, credentialService.Object, transProvider.Object, securityEventSink.Object);

        var response = await pipeline.LoginAsync(context, assertion);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.Status, Is.EqualTo(AuthenticationStatus.Failed));
        }
        securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e => e.EventType == AshlarSecurityEventTypes.AuthenticationFailed && e.FailureReason == SecurityEventFailureReasons.CredentialUpdateFailed), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void ExternalProvidersCoverage()
    {
        var oidc = new OidcAuthenticationProvider("Google");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(oidc.Key.Name, Is.EqualTo("Google"));
            Assert.That(oidc.TypicalCredentialLength, Is.EqualTo(512));
        }

        var oauth = new OAuthAuthenticationProvider("GitHub");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(oauth.Key.Name, Is.EqualTo("GitHub"));
            Assert.That(oauth.TypicalCredentialLength, Is.EqualTo(256));
        }

        var saml = new Saml2AuthenticationProvider("Okta");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(saml.Key.Name, Is.EqualTo("Okta"));
            Assert.That(saml.TypicalCredentialLength, Is.EqualTo(3072));
        }
    }

    private static UserCredential CreateCredential(Guid userId, string value, string key)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.RecoveryCode,
            ProviderName = "RecoveryCode",
            ProviderKey = key,
            CredentialValue = value,
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
    }

    private static RecoveryCodeService CreateServiceForGenerationValidation(RecoveryCodeOptions options)
    {
        var repository = new Mock<IIdentityRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();

        repository.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => new User { Id = id, Email = "test@example.com", IsActive = true });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Mock<IAshlarTransaction>().Object);

        return new RecoveryCodeService(repository.Object, transactionProvider.Object, new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(options));
    }

    private sealed class DefaultResolveCredentialProvider : IAuthenticationProvider
    {
        public AuthenticationProviderKey Key => new(ProviderType.Local, "Default");
        public bool ProtectsCredentials => false;
        public int TypicalCredentialLength => 0;
        public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => string.Empty;
        public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;
        public Task<IUser?> FindUserAsync(IAuthenticationAssertion assertion, AuthenticationContext context, IIdentityRepository repository, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
        public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default) => Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
    }
}



