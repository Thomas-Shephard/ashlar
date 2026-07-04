using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Security.Encryption;
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
        var repo = new Mock<IUserRepository>().Object;
        var credentialRepo = new Mock<ICredentialRepository>().Object;
        var trans = new Mock<IAshlarTransactionProvider>().Object;
        var hasher = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());

        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(null!, credentialRepo, trans, hasher, CreateDependencies(options)));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, null!, trans, hasher, CreateDependencies(options)));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, credentialRepo, trans, null!, CreateDependencies(options)));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, credentialRepo, trans, hasher, CreateDependencies(null!)));

        var optionsMock = new Mock<IOptions<RecoveryCodeOptions>>();
        optionsMock.SetupGet(o => o.Value).Returns((RecoveryCodeOptions)null!);
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, credentialRepo, trans, hasher, CreateDependencies(optionsMock.Object)));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncReturnsExpectedCount()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 5, ExpiresAfter = TimeSpan.FromDays(1) });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options));

        var result = await service.GenerateRecoveryCodesPrivilegedAsync(userId, new RecoveryCodeGenerationRequest { Audit = new AuditContext(IpAddress: "203.0.113.51") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Has.Count.EqualTo(5));
        }
        credentialRepository.Verify(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()), Times.Once);
        credentialRepository.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c => c.Purpose == "recovery-code" && c.ExpiresAt != null), It.IsAny<CancellationToken>()), Times.Exactly(5));
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldRejectMissingOrMismatchedFreshMfaProof()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());

        var missing = await service.GenerateRecoveryCodesAsync(userId);
        var mismatched = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest
        {
            FreshMfaProof = CreateProof(Guid.NewGuid(), tenant),
            Tenant = tenant
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.Succeeded, Is.False);
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(mismatched.Succeeded, Is.False);
            Assert.That(mismatched.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldRejectGlobalProofForAnotherUser()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest
        {
            FreshMfaProof = CreateProof(Guid.NewGuid())
        });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldRejectTenantProofForGlobalRequest()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest
        {
            FreshMfaProof = CreateProof(userId, new TenantContext(Guid.NewGuid()))
        });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldRejectExpiredFreshMfaProof()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId, expiresAt: DateTimeOffset.UtcNow.AddSeconds(-1));

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId
        });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldRejectProofForAnotherSession()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);

        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest
        {
            FreshMfaProof = proof,
            CurrentSessionId = Guid.NewGuid()
        });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncWithRequestOverridesOptions()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 5 });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options));

        var request = new RecoveryCodeGenerationRequest { CodeCount = 3, ReplaceExisting = false, ExpiresAfter = TimeSpan.FromHours(1) };
        var result = await service.GenerateRecoveryCodesPrivilegedAsync(userId, request with { Audit = new AuditContext(ActorUserId: userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Has.Count.EqualTo(3));
        }
        credentialRepository.Verify(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()), Times.Never);
        credentialRepository.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c => c.ExpiresAt != null), It.IsAny<CancellationToken>()), Times.Exactly(3));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncPropagatesAuditToEventAndNotification()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
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
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });
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
        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options, securityEventSink: securityEvents.Object, notificationService: notificationService.Object));

        var result = await service.GenerateRecoveryCodesPrivilegedAsync(userId, new RecoveryCodeGenerationRequest { Audit = audit });

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
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var notificationService = new Mock<ISecurityNotificationService>();
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });
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
        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options, notificationService: notificationService.Object));

        var proof = CreateProof(userId);
        var result = await service.GenerateRecoveryCodesAsync(userId, new RecoveryCodeGenerationRequest { FreshMfaProof = proof, CurrentSessionId = proof.SessionId });

        Assert.That(result.Succeeded, Is.True);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.RecoveryCodesGenerated &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncWithNoExpiryCreatesNonExpiringCredentials()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions { CodeCount = 1, ExpiresAfter = null });
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction.Object);

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options));

        var result = await service.GenerateRecoveryCodesPrivilegedAsync(userId, new RecoveryCodeGenerationRequest { Audit = new AuditContext(IpAddress: "203.0.113.51") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Has.Count.EqualTo(1));
        }
        credentialRepository.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(c => c.ExpiresAt == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void ServiceGenerateRecoveryCodesAsyncThrowsOnInvalidUserId()
    {
        var service = new RecoveryCodeService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions())));
        Assert.That(async () => await service.GenerateRecoveryCodesPrivilegedAsync(Guid.Empty, new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) }), Throws.ArgumentException);
        Assert.That(async () => await service.GenerateRecoveryCodesAsync(Guid.Empty), Throws.ArgumentException);
    }

    [Test]
    public void ServiceGenerateRecoveryCodesPrivilegedAsyncShouldRequireAudit()
    {
        var service = new RecoveryCodeService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions())));

        Assert.ThrowsAsync<ArgumentException>(() => service.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid()));
    }

    [Test]
    public void ServiceGenerateRecoveryCodesPrivilegedAsyncShouldRejectNullRequest()
    {
        var service = new RecoveryCodeService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions())));

        Assert.ThrowsAsync<ArgumentException>(() => service.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), null!));
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncFailsIfUserNotFound()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((IUser?)null);

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Mock<IAshlarTransaction>().Object);

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options));

        var result = await service.GenerateRecoveryCodesPrivilegedAsync(userId, new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldRejectTenantMismatchBeforeGeneratingCodes()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var securityEvents = new Mock<ISecurityEventSink>();
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = Guid.NewGuid() });

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options, securityEventSink: securityEvents.Object));

        var result = await service.GenerateRecoveryCodesPrivilegedAsync(userId, new RecoveryCodeGenerationRequest { ReplaceExisting = true, Tenant = new TenantContext(requestedTenantId), Audit = new AuditContext(ActorUserId: userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(result.Value, Is.Null);
            credentialRepository.Verify(r => r.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            credentialRepository.Verify(r => r.CreateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
            transactionProvider.Verify(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
            securityEvents.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
                e.EventType == AshlarSecurityEventTypes.RecoveryCodesGenerated &&
                e.Outcome == SecurityEventOutcomes.Failure &&
                e.UserId == userId &&
                e.TenantId == requestedTenantId &&
                e.FailureReason == AshlarFailureCodes.TenantMismatch.Value &&
                e.Properties == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public async Task ServiceGenerateRecoveryCodesAsyncShouldTreatMissingTenantAsGlobalOnly()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 }, Guid.NewGuid());

        var result = await service.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
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

        var tooManyResult = await service.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), tooMany);
        var zeroResult = await service.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), zero);
        var negativeExpiryResult = await service.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), negativeExpiry);

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
        var invalidCodeLengthResult = await invalidCodeLength.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), request);
        var invalidGroupSizeResult = await invalidGroupSize.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), request);

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
            Mock.Of<IUserRepository>(),
            Mock.Of<ICredentialRepository>(),
            Mock.Of<IAshlarTransactionProvider>(provider => provider.BeginTransactionAsync(It.IsAny<CancellationToken>()) == Task.FromResult(Mock.Of<IAshlarTransaction>())),
            new PasswordHasherSelector([new PasswordHasherV1()]),
            CreateDependencies(Options.Create(new RecoveryCodeOptions())));
        var invalidCount = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 0 });
        var invalidConfiguration = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeLength = 0 });
        var invalidExpiry = CreateServiceForGenerationValidation(new RecoveryCodeOptions { ExpiresAfter = TimeSpan.Zero });

        var missingUserResult = await missingUser.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) });
        var invalidCountResult = await invalidCount.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) });
        var invalidConfigurationResult = await invalidConfiguration.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) });
        var invalidExpiryResult = await invalidExpiry.GenerateRecoveryCodesPrivilegedAsync(Guid.NewGuid(), new RecoveryCodeGenerationRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) });

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
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var securityEvents = new RecordingSecurityEventSink();
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });
        credentialRepository.Setup(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()))
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

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options, securityEventSink: securityEvents));

        var result1 = await service.RevokeRecoveryCodesPrivilegedAsync(userId, new RevokeRecoveryCodesRequest { Reason = "test reason", Audit = new AuditContext(ActorUserId: userId) });
        Assert.That(result1, Is.EqualTo(10));

        var proof = CreateProof(userId);
        var result2 = await service.RevokeRecoveryCodesAsync(userId, new RevokeRecoveryCodesRequest { FreshMfaProof = proof, CurrentSessionId = proof.SessionId });
        Assert.That(result2, Is.EqualTo(10));

        credentialRepository.Verify(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()), Times.Exactly(2));
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(securityEvents.Events, Has.Count.EqualTo(2));
            Assert.That(securityEvents.Events[0].EventType, Is.EqualTo(AshlarSecurityEventTypes.RecoveryCodesRevoked));
            Assert.That(securityEvents.Events[0].Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvents.Events[0].FailureReason, Is.Null);
            Assert.That(securityEvents.Events[0].Properties, Does.ContainKey("count").WithValue("10"));
            Assert.That(securityEvents.Events[0].Properties, Does.ContainKey("revoked").WithValue("true"));
            Assert.That(securityEvents.Events[0].Properties, Does.ContainKey("reason").WithValue("test reason"));
            Assert.That(securityEvents.Events[1].Properties, Does.ContainKey("count").WithValue("10"));
            Assert.That(securityEvents.Events[1].Properties, Does.ContainKey("revoked").WithValue("true"));
            Assert.That(securityEvents.Events[1].Properties, Does.Not.ContainKey("reason"));
            Assert.That(string.Join("|", securityEvents.Events.SelectMany(e => e.Properties?.Values ?? [])), Does.Not.Contain("RECOVERY-CODE").And.Not.Contain("hash"));
        }
    }

    [Test]
    public async Task ServiceRevokeRecoveryCodesAsyncShouldRejectMissingOrMismatchedFreshMfaProof()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var proof = CreateProof(userId);

        var missing = await service.RevokeRecoveryCodesAsync(userId);
        var mismatched = await service.RevokeRecoveryCodesAsync(userId, new RevokeRecoveryCodesRequest
        {
            FreshMfaProof = CreateProof(userId, new TenantContext(Guid.NewGuid())),
            Tenant = tenant
        });
        var wrongSession = await service.RevokeRecoveryCodesAsync(userId, new RevokeRecoveryCodesRequest
        {
            FreshMfaProof = proof,
            CurrentSessionId = Guid.NewGuid()
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing, Is.Zero);
            Assert.That(mismatched, Is.Zero);
            Assert.That(wrongSession, Is.Zero);
        }
    }

    [Test]
    public async Task ServiceRevokeRecoveryCodesAsyncAuditsNoOpCount()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var securityEvents = new RecordingSecurityEventSink();
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });
        credentialRepository.Setup(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
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
        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options, securityEventSink: securityEvents));

        var count = await service.RevokeRecoveryCodesPrivilegedAsync(userId, new RevokeRecoveryCodesRequest { Reason = "admin cleanup", Audit = new AuditContext(ActorUserId: userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count, Is.Zero);
            var securityEvent = securityEvents.Events.Single();
            Assert.That(securityEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.RecoveryCodesRevoked));
            Assert.That(securityEvent.Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(securityEvent.FailureReason, Is.Null);
            Assert.That(securityEvent.Properties, Does.ContainKey("count").WithValue("0"));
            Assert.That(securityEvent.Properties, Does.ContainKey("revoked").WithValue("false"));
            Assert.That(securityEvent.Properties, Does.ContainKey("reason").WithValue("admin cleanup"));
        }
    }

    [Test]
    public async Task ServiceRevokeRecoveryCodesAsyncShouldRejectTenantMismatchBeforeRevokingCredentials()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var securityEvents = new Mock<ISecurityEventSink>();
        var options = Options.Create(new RecoveryCodeOptions());
        var userId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = Guid.NewGuid() });

        var service = new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, hasherSelector, CreateDependencies(options, securityEventSink: securityEvents.Object));

        var result = await service.RevokeRecoveryCodesPrivilegedAsync(userId, new RevokeRecoveryCodesRequest { Reason = "admin", Tenant = new TenantContext(requestedTenantId), Audit = new AuditContext(ActorUserId: userId) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.Zero);
            credentialRepository.Verify(r => r.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            transactionProvider.Verify(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
            securityEvents.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
                e.EventType == AshlarSecurityEventTypes.RecoveryCodesRevoked &&
                e.Outcome == SecurityEventOutcomes.Failure &&
                e.TenantId == requestedTenantId &&
                e.FailureReason == AshlarFailureCodes.TenantMismatch.Value &&
                e.Properties == null), It.IsAny<CancellationToken>()), Times.Once);
        }
    }

    [Test]
    public void ServiceRevokeRecoveryCodesAsyncThrowsOnInvalidUserId()
    {
        var service = new RecoveryCodeService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions())));
        Assert.That(async () => await service.RevokeRecoveryCodesPrivilegedAsync(Guid.Empty, new RevokeRecoveryCodesRequest { Audit = new AuditContext(ActorUserId: Guid.NewGuid()) }), Throws.ArgumentException);
        Assert.That(async () => await service.RevokeRecoveryCodesAsync(Guid.Empty), Throws.ArgumentException);
    }

    [Test]
    public void ServiceRevokeRecoveryCodesPrivilegedAsyncShouldRequireAudit()
    {
        var service = new RecoveryCodeService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions())));

        Assert.ThrowsAsync<ArgumentException>(() => service.RevokeRecoveryCodesPrivilegedAsync(Guid.NewGuid()));
    }

    [Test]
    public void ServiceRevokeRecoveryCodesPrivilegedAsyncShouldRejectNullRequest()
    {
        var service = new RecoveryCodeService(new Mock<IUserRepository>().Object, new Mock<ICredentialRepository>().Object, new Mock<IAshlarTransactionProvider>().Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions())));

        Assert.ThrowsAsync<ArgumentException>(() => service.RevokeRecoveryCodesPrivilegedAsync(Guid.NewGuid(), null!));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ProviderConstructorThrowsOnNull()
    {
        var hasher = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());

        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(null!, options));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(hasher, null!));

        var optionsMock = new Mock<IOptions<RecoveryCodeOptions>>();
        optionsMock.SetupGet(o => o.Value).Returns((RecoveryCodeOptions)null!);
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeAuthenticationProvider(hasher, optionsMock.Object));
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsMatchedCredential()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var credentialRepository = new Mock<ICredentialRepository>();
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

        credentialRepository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credentials[0]);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, options);
        var assertion = new RecoveryCodeAssertion(rawCode);
        var context = new AuthenticationContext(IpAddress: "1.2.3.4");

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(userId, assertion, context, credentialRepository.Object);

        Assert.That(result, Is.Not.Null);
        Assert.That(result.ProviderKey, Is.EqualTo(providerKey));
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfNoMatch()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var credentialRepository = new Mock<ICredentialRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "code1";
        var secretCode = "WRONG-CODE";
        var rawCode = $"{providerKey}-{secretCode}";

        credentialRepository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateCredential(userId, "bad-hash", providerKey));

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(userId, assertion, null, credentialRepository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfCredentialIsMissing()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var credentialRepository = new Mock<ICredentialRepository>();
        var userId = Guid.NewGuid();
        var rawCode = "code1-ABCD-EFGH-IJKL";

        credentialRepository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(userId, assertion, null, credentialRepository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullIfExpired()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var credentialRepository = new Mock<ICredentialRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "code1";
        var secretCode = "ABCD-EFGH-IJKL";
        var rawCode = $"{providerKey}-{secretCode}";
        var hashedCode = Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(secretCode));

        var expired = CreateCredential(userId, hashedCode, providerKey);
        expired.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        credentialRepository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(expired);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(userId, assertion, null, credentialRepository.Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullForUnsupportedAssertion()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, null, new Mock<ICredentialRepository>().Object);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullForMalformedCode()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, Options.Create(new RecoveryCodeOptions()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(Guid.NewGuid(), new RecoveryCodeAssertion("CODE"), null, new Mock<ICredentialRepository>().Object), Is.Null);
            Assert.That(await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(Guid.NewGuid(), new RecoveryCodeAssertion("CODE-"), null, new Mock<ICredentialRepository>().Object), Is.Null);
        }
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsNullForOverlongCodeWithoutRepositoryOrHashingWork()
    {
        const int maximumDefaultSubmittedCodeLength = 52;
        var hasher = new RecordingPasswordHasher();
        var hasherSelector = new PasswordHasherSelector([hasher]);
        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, Options.Create(new RecoveryCodeOptions()));
        var credentialRepository = new Mock<ICredentialRepository>(MockBehavior.Strict);

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(Guid.NewGuid(), new RecoveryCodeAssertion(new string('A', maximumDefaultSubmittedCodeLength + 1)), null, credentialRepository.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.Null);
            Assert.That(hasher.VerifyCalls, Is.Zero);
        }

        credentialRepository.Verify(
            r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncAcceptsMaximumFormattedDefaultLength()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var credentialRepository = new Mock<ICredentialRepository>();
        var userId = Guid.NewGuid();
        var idCode = "ABCDE";
        var secretCode = "ABCD-EFGH-IJKL";
        var rawCode = $"{idCode}-{secretCode}{new string(' ', 32)}";
        var hashedCode = Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(secretCode));
        var credential = CreateCredential(userId, hashedCode, idCode);

        credentialRepository
            .Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", $"{userId:N}-{idCode}", It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, options);

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(userId, new RecoveryCodeAssertion(rawCode), null, credentialRepository.Object);

        Assert.That(result, Is.SameAs(credential));
    }

    [Test]
    public async Task ProviderAuthenticateAsyncSucceedsIfCredentialNotNull()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
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
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        var assertion = new RecoveryCodeAssertion("SOME-CODE");

        var result = await provider.AuthenticateAsync(assertion, null);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task PipelineShouldFailGenericallyWhenRecoveryCodeUserIdResolvesWrongTenant()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com", TenantId = otherTenantId };
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, Options.Create(new RecoveryCodeOptions()));
        var registry = new AuthenticationProviderRegistry([provider]);
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var events = new RecordingSecurityEventSink();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        var transactionProvider = new NullTransactionProvider();
        var credentialService = new CredentialService(
            repository.Object,
            credentialRepository.Object,
            Mock.Of<ISecretProtector>(),
            transactionProvider);
        var pipeline = new AuthenticationPipeline(
            registry,
            credentialService,
            transactionProvider,
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(SecurityEventSink: events));
        var context = new AuthenticationContext(TenantId: tenantId, UserId: userId);

        var response = await pipeline.LoginAsync(context, new RecoveryCodeAssertion("ABCD-EFGH-IJKL"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(response.User, Is.Null);
            Assert.That(events.Events.Single().FailureReason, Is.EqualTo(SecurityEventFailureReasons.InvalidCredentials));
            Assert.That(events.Events.Single().UserId, Is.Null);
        }
        credentialRepository.Verify(r => r.GetCredentialForUserAsync(userId, It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void DiRegistrationResolvesServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new Mock<IUserRepository>().Object);
        services.AddSingleton(new Mock<ICredentialRepository>().Object);
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
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.TypicalCredentialLength, Is.EqualTo(128));
            Assert.That(provider.ProtectsCredentials, Is.False);
            Assert.That(provider.FactorType, Is.EqualTo(AuthenticationFactorTypes.RecoveryCode));
            Assert.That(provider.CanSatisfyFactor(AuthenticationFactorTypes.RecoveryCode), Is.True);
            Assert.That(provider.CanSatisfyFactor(AuthenticationFactorTypes.Totp), Is.False);
            Assert.That(provider.CanSatisfyBackupFactor(AuthenticationFactorTypes.Totp), Is.True);
            Assert.That(provider, Is.Not.AssignableTo<IPrimaryAuthenticationProvider>());
            Assert.That(provider, Is.AssignableTo<ISecondaryAuthenticationFactorProvider>());
            Assert.That(provider, Is.AssignableTo<IBackupAuthenticationFactorProvider>());
            Assert.That(provider.CanSatisfyFactor(" "), Is.False);
            Assert.That(provider.CanSatisfyBackupFactor(" "), Is.False);
        }
    }

    [Test]
    public void ProviderGetProviderKeyShouldDeriveRecoveryCodeStorageKey()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        var userId = Guid.NewGuid();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion("abcde-secret"), userId), Is.EqualTo($"{userId:N}-ABCDE"));
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion("ab cde-secret"), userId), Is.EqualTo($"{userId:N}-ABCDE"));
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion("CODE"), userId), Is.Empty);
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion("CODE-"), userId), Is.Empty);
            Assert.That(provider.GetProviderKey(new RecoveryCodeAssertion(new string('A', 128) + "-SECRET"), userId), Is.Empty);
            Assert.That(provider.GetProviderKey(new Mock<IAuthenticationAssertion>().Object, userId), Is.Empty);
            Assert.That(provider, Is.InstanceOf<IAuthenticationCredentialResolver>());
        }
    }

    [Test]
    public void ProviderPrepareCredentialValueReturnsHashedValue()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, Options.Create(new RecoveryCodeOptions()));
        var assertion = new RecoveryCodeAssertion("SOME-CODE");

        var prepared = provider.PrepareCredentialValue(assertion, "RAW-VALUE");

        Assert.That(prepared, Is.Not.Null);
        Assert.That(prepared, Is.Not.EqualTo("RAW-VALUE"));
    }

    [Test]
    public void ProviderPrepareCredentialValueReturnsNullIfEmpty()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.PrepareCredentialValue(new RecoveryCodeAssertion("CODE"), " "), Is.Null);
            Assert.That(provider.PrepareCredentialValue(new RecoveryCodeAssertion("CODE"), null), Is.Null);
        }
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsUserByEmail()
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        var context = new AuthenticationContext(Email: "test@example.com");
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "test@example.com" };

        repository.Setup(r => r.GetUserByEmailAsync("test@example.com", It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var found = await ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), context, repository.Object);

        Assert.That(found, Is.Not.Null);
        Assert.That(found.Id, Is.EqualTo(user.Id));
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsNullForUserIdBecauseCredentialServiceOwnsFallback()
    {
        var repository = new Mock<IUserRepository>();
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        var userId = Guid.NewGuid();
        var context = new AuthenticationContext(Email: "other@example.com", UserId: userId);
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);
        repository.Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = Guid.NewGuid(), DisplayEmail = "other@example.com" });

        var found = await ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), context, repository.Object);

        Assert.That(found, Is.Null);
        repository.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        repository.Verify(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncResilientToWhitespaceAndCasing()
    {
        var hasherSelector = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var credentialRepository = new Mock<ICredentialRepository>();
        var userId = Guid.NewGuid();
        var providerKey = "CODE1";
        var secretCode = "ABCD-EFGH-IJKL";
        var rawCode = "  code 1 - abcd - efgh - ijkl  "; // Mixed casing and spaces
        var hashedCode = Convert.ToBase64String(hasherSelector.DefaultHasher.HashPassword(secretCode));

        credentialRepository.Setup(r => r.GetCredentialForUserAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateCredential(userId, hashedCode, providerKey));

        var provider = new RecoveryCodeAuthenticationProvider(hasherSelector, options);
        var assertion = new RecoveryCodeAssertion(rawCode);

        var result = await ((IAuthenticationCredentialResolver)provider).ResolveCredentialAsync(userId, assertion, null, credentialRepository.Object);

        Assert.That(result, Is.Not.Null);
        Assert.That(result.ProviderKey, Is.EqualTo(providerKey));
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsNullOnWrongConditions()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));

        using (Assert.EnterMultipleScope())
        {
            // Wrong assertion
            Assert.That(await ((IAuthenticationUserResolver)provider).FindUserAsync(new Mock<IAuthenticationAssertion>().Object, new AuthenticationContext(Email: "test@example.com"), new Mock<IUserRepository>().Object), Is.Null);

            // Missing email (empty, whitespace, and null)
            Assert.That(await ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(Email: ""), new Mock<IUserRepository>().Object), Is.Null);
            Assert.That(await ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(Email: " "), new Mock<IUserRepository>().Object), Is.Null);
            Assert.That(await ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(Email: null), new Mock<IUserRepository>().Object), Is.Null);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ProviderFindUserAsyncThrowsOnNullArguments()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        Assert.ThrowsAsync<ArgumentNullException>(() => ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), null!, new Mock<IUserRepository>().Object));
        Assert.ThrowsAsync<ArgumentNullException>(() => ((IAuthenticationUserResolver)provider).FindUserAsync(new RecoveryCodeAssertion("CODE"), new AuthenticationContext(), null!));
    }

    [Test]
    public void ProviderAuthenticateAsyncThrowsOnWrongAssertionType()
    {
        var provider = new RecoveryCodeAuthenticationProvider(new PasswordHasherSelector([new PasswordHasherV1()]), Options.Create(new RecoveryCodeOptions()));
        Assert.That(async () => await provider.AuthenticateAsync(new Mock<IAuthenticationAssertion>().Object, null), Throws.ArgumentException);
    }

    [Test]
    public void AuthenticationProviderShouldNotResolveCredentialsByDefault()
    {
        IAuthenticationProvider provider = new DefaultResolveCredentialProvider();

        Assert.That(provider, Is.Not.InstanceOf<IAuthenticationCredentialResolver>());
    }


    [Test]
    public async Task PipelineHandlesInconsistentCredentialState()
    {
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var credentialService = new Mock<ICredentialService>();
        var transProvider = new Mock<IAshlarTransactionProvider>();
        var securityEventSink = new Mock<ISecurityEventSink>();

        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active };
        var assertion = new RecoveryCodeAssertion("CODE");
        var context = new AuthenticationContext(Email: "test@example.com");

        var provider = new Mock<IPrimaryAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(AuthenticationProviderKey.Local);

        IAuthenticationProvider? providerObj = provider.Object;
        providerRegistry.Setup(r => r.TryGetProvider(assertion, out providerObj)).Returns(true);

        // Setup: ResolveAsync returns NULL credential
        credentialService.Setup(s => s.ResolveAsync(context, assertion, provider.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync((user, null, null, false));

        // Setup: AuthenticateAsync returns SUCCESS but requests consumption
        provider.Setup(p => p.AuthenticateAsync(assertion, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));

        var pipeline = new AuthenticationPipeline(
            providerRegistry.Object,
            credentialService.Object,
            transProvider.Object,
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(SecurityEventSink: securityEventSink.Object));

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

    private static RecoveryCodeService CreateServiceForGenerationValidation(RecoveryCodeOptions options, Guid? userTenantId = null)
    {
        var repository = new Mock<IUserRepository>();
        var credentialRepository = new Mock<ICredentialRepository>();
        var transactionProvider = new Mock<IAshlarTransactionProvider>();

        repository.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => new User { Id = id, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active, TenantId = userTenantId });

        transactionProvider.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Mock<IAshlarTransaction>().Object);

        return new RecoveryCodeService(repository.Object, credentialRepository.Object, transactionProvider.Object, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(options)));
    }

    private static RecoveryCodeServiceDependencies CreateDependencies(
        IOptions<RecoveryCodeOptions> options,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null,
        ISecurityNotificationService? notificationService = null)
    {
        return new RecoveryCodeServiceDependencies(options, timeProvider, securityEventSink, notificationService);
    }

    private static FreshMfaVerificationProof CreateProof(Guid userId, TenantContext? tenant = null, DateTimeOffset? expiresAt = null)
    {
        var verifiedAt = DateTimeOffset.UtcNow;
        return new FreshMfaVerificationProof(userId, tenant?.TenantId, Guid.NewGuid(), verifiedAt, expiresAt ?? verifiedAt.AddMinutes(10));
    }

    private sealed class DefaultResolveCredentialProvider : IAuthenticationProvider
    {
        public AuthenticationProviderKey Key => new(ProviderType.Local, "Default");
        public bool ProtectsCredentials => false;
        public int TypicalCredentialLength => 0;
        public string GetProviderKey(IAuthenticationAssertion assertion, Guid userId) => string.Empty;
        public string? PrepareCredentialValue(IAuthenticationAssertion assertion, string? rawValue) => rawValue;
        public Task<AuthenticationResult> AuthenticateAsync(IAuthenticationAssertion assertion, UserCredential? credential, CancellationToken cancellationToken = default) => Task.FromResult(new AuthenticationResult(AuthenticationResultStatus.Failed));
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingPasswordHasher : IPasswordHasher
    {
        public byte Version => 1;
        public int VerifyCalls { get; private set; }
        public byte[] HashPassword(ReadOnlySpan<char> password) => [Version];

        public bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash)
        {
            VerifyCalls++;
            return false;
        }
    }
}
