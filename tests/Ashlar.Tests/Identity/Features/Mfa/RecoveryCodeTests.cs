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
    public void GenerationRequestUsesDefaultSettings()
    {
        var actorId = Guid.NewGuid();
        var proof = CreateProof(actorId);
        var request = new RecoveryCodeGenerationRequest(actorId,
            new AccountSecurityActorContext(actorId, TenantContext.Global, proof.SessionId, proof,
                new AuditContext(actorId)), TenantContext.Global);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.ReplaceExisting, Is.True);
            Assert.That(request.CodeCount, Is.Null);
            Assert.That(request.ExpiresAfter, Is.Null);
        }
    }

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
        var composition = new DurableSecurityMutationTestComposition(participants: [repo, credentialRepo]);
        var trans = composition.Transactions;
        var hasher = new PasswordHasherSelector([new PasswordHasherV1()]);
        var options = Options.Create(new RecoveryCodeOptions());
        var dependencies = CreateDependencies(options, securityEventSink: composition.Events);

        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(null!, credentialRepo, trans, hasher, dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, null!, trans, hasher, dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, credentialRepo, trans, null!, dependencies));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, credentialRepo, trans, hasher, CreateDependencies(null!)));

        var optionsMock = new Mock<IOptions<RecoveryCodeOptions>>();
        optionsMock.SetupGet(o => o.Value).Returns((RecoveryCodeOptions)null!);
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeService(repo, credentialRepo, trans, hasher, CreateDependencies(optionsMock.Object)));
        Assert.Throws<ArgumentNullException>(() => _ = new RecoveryCodeServiceDependencies(options, ProofValidator(null), authorizer: null));
    }

    [Test]
    public async Task ServicePublicGenerationRequiresValidActorProofAndAuthorization()
    {
        var actorId = Guid.NewGuid();
        var proof = CreateProof(actorId);
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 });

        var mismatch = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, proof,
            audit: new AuditContext(ActorUserId: Guid.NewGuid())));
        var staleProof = CreateProof(actorId, expiresAt: DateTimeOffset.UtcNow.AddSeconds(-1));
        var stale = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, staleProof));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(mismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(stale.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
        }
    }

    [Test]
    public async Task ServicePublicGenerationPassesCompleteContextToHostAuthorizer()
    {
        var actorId = Guid.NewGuid();
        var targetId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var proof = CreateProof(actorId, tenant);
        AccountSecurityAuthorizationContext? observed = null;
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()))
            .Callback<AccountSecurityAuthorizationContext, CancellationToken>((context, _) => observed = context)
            .ReturnsAsync(false);
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 },
            authorizer: authorizer.Object);

        var result = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, proof,
            targetId, tenant));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(observed, Is.Not.Null);
            Assert.That(observed!.ActorUserId, Is.EqualTo(actorId));
            Assert.That(observed.TargetUserId, Is.EqualTo(targetId));
            Assert.That(observed.TargetTenant, Is.EqualTo(tenant));
            Assert.That(observed.Operation, Is.EqualTo(AccountSecurityOperation.GenerateRecoveryCodes));
            Assert.That(observed.CurrentSessionId, Is.EqualTo(proof.SessionId));
        }
    }

    [Test]
    public async Task ServicePublicGenerationAndRevocationSucceedThroughAuthorizedRequests()
    {
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);
        var repository = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var transactions = new RecordingTransactionProvider();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });
        credentials.Setup(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>()))
            .ReturnsAsync(2);
        var composition = DurableSecurityMutationTestComposition.Create(transactions, participants: [repository.Object, credentials.Object]);
        var service = new RecoveryCodeService(repository.Object, credentials.Object, composition.Transactions,
            new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions { CodeCount = 1 }),
                securityEventSink: composition.Events));

        var generated = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(userId, proof));
        var revoked = await service.RevokeRecoveryCodesAsync(CreateRevocationRequest(userId, proof, reason: "cleanup"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(generated.Succeeded, Is.True);
            Assert.That(generated.Value, Has.Count.EqualTo(1));
            Assert.That(revoked.Succeeded, Is.True);
            Assert.That(revoked.Value, Is.EqualTo(2));
        }
    }

    [Test]
    public async Task ServicePublicGenerationRejectsInvalidOptionsBeforeAuthorization()
    {
        var actorId = Guid.NewGuid();
        var proof = CreateProof(actorId);
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        var events = new Mock<ISecurityEventSink>();
        var credentials = new Mock<ICredentialRepository>();
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 5 }, authorizer: authorizer.Object,
            securityEventSink: events.Object, credentialRepository: credentials.Object);

        var zero = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, proof, codeCount: 0));
        var tooMany = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, proof, codeCount: 11));
        var expiry = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, proof, expiresAfter: TimeSpan.Zero));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(zero.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCodeCount));
            Assert.That(tooMany.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCodeCount));
            Assert.That(expiry.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidExpiry));
        }
        authorizer.Verify(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()), Times.Never);
        events.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.RecoveryCodesGenerated && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actorId && e.ActorUserId == actorId && e.Provider == new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode") &&
            (e.FailureReason == AshlarFailureCodes.InvalidCodeCountValue || e.FailureReason == AshlarFailureCodes.InvalidExpiryValue)),
            It.IsAny<CancellationToken>()), Times.Exactly(3));
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public void ServiceExecutorRejectsEmptyUserId()
    {
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions());
        var audit = new AuditContext(ActorUserId: Guid.NewGuid());
        var executor = (IRecoveryCodeMutationExecutor)service;

        Assert.ThrowsAsync<ArgumentException>(() => executor.GenerateRecoveryCodesAsync(Guid.Empty,
            new RecoveryCodeGenerationExecutionRequest(audit, TenantContext.Global, false, null, true, 1, null)));
        Assert.ThrowsAsync<ArgumentException>(() => executor.RevokeRecoveryCodesAsync(Guid.Empty,
            new RevokeRecoveryCodesExecutionRequest(audit, TenantContext.Global, false, null)));
    }

    [Test]
    public async Task ServiceExecutorGenerationCoversValidationBranches()
    {
        var userId = Guid.NewGuid();
        var audit = new AuditContext(ActorUserId: userId);
        var invalidCount = (IRecoveryCodeMutationExecutor)CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 0 });
        var invalidConfiguration = (IRecoveryCodeMutationExecutor)CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeLength = 0 });
        var invalidGroup = (IRecoveryCodeMutationExecutor)CreateServiceForGenerationValidation(new RecoveryCodeOptions { GroupSize = 0 });
        var invalidExpiry = (IRecoveryCodeMutationExecutor)CreateServiceForGenerationValidation(new RecoveryCodeOptions { ExpiresAfter = TimeSpan.Zero });

        var count = await invalidCount.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit));
        var configuration = await invalidConfiguration.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit));
        var group = await invalidGroup.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit));
        var expiry = await invalidExpiry.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(count.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCodeCount));
            Assert.That(configuration.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidConfiguration));
            Assert.That(group.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidConfiguration));
            Assert.That(expiry.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidExpiry));
        }
    }

    [Test]
    public async Task ServiceExecutorGenerationSupportsNoReplacementAndNoExpiry()
    {
        var userId = Guid.NewGuid();
        var repository = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var transactions = new RecordingTransactionProvider();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active });
        var composition = DurableSecurityMutationTestComposition.Create(transactions, participants: [repository.Object, credentials.Object]);
        var service = new RecoveryCodeService(repository.Object, credentials.Object, composition.Transactions,
            new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(new RecoveryCodeOptions { CodeCount = 1, ExpiresAfter = null }),
                securityEventSink: composition.Events));

        var result = await ((IRecoveryCodeMutationExecutor)service).GenerateRecoveryCodesAsync(userId,
            GenerationExecution(new AuditContext(ActorUserId: userId), replaceExisting: false));

        Assert.That(result.Succeeded, Is.True);
        credentials.Verify(r => r.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(credential => credential.ExpiresAt == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServiceExecutorRejectsMissingAndMismatchedScopedUsers()
    {
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var audit = new AuditContext(ActorUserId: userId);
        var repository = new Mock<IUserRepository>();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);
        var service = CreateService(repository.Object, new RecoveryCodeOptions());
        var executor = (IRecoveryCodeMutationExecutor)service;

        var missing = await executor.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit));
        var allTenantsMissing = await executor.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit, tenant: null, includeAllTenants: true));

        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, TenantId = Guid.NewGuid(), DisplayEmail = "wrong@example.com" });
        var mismatch = await executor.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit, tenant: tenant));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(allTenantsMissing.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(mismatch.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task ServiceExecutorRevalidatesScopeAfterLockForGenerationAndRevocation()
    {
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active };
        var repository = new Mock<IUserRepository>();
        repository.SetupSequence(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user).ReturnsAsync((IUser?)null).ReturnsAsync(user).ReturnsAsync((IUser?)null);
        var service = CreateService(repository.Object, new RecoveryCodeOptions());
        var executor = (IRecoveryCodeMutationExecutor)service;
        var audit = new AuditContext(ActorUserId: userId);

        var generation = await executor.GenerateRecoveryCodesAsync(userId, GenerationExecution(audit));
        var revocation = await executor.RevokeRecoveryCodesAsync(userId, RevocationExecution(audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(generation.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(revocation.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [Test]
    public async Task ServiceExecutorRevocationCoversMissingUserAndReasonBranches()
    {
        var userId = Guid.NewGuid();
        var audit = new AuditContext(ActorUserId: userId);
        var missing = (IRecoveryCodeMutationExecutor)CreateService(Mock.Of<IUserRepository>(), new RecoveryCodeOptions());
        var missingResult = await missing.RevokeRecoveryCodesAsync(userId, RevocationExecution(audit));

        var events = new RecordingSecurityEventSink();
        var repository = new Mock<IUserRepository>();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>())).ReturnsAsync(0);
        var service = CreateService(repository.Object, new RecoveryCodeOptions(), credentials.Object, securityEvents: events);
        var result = await ((IRecoveryCodeMutationExecutor)service).RevokeRecoveryCodesAsync(userId, RevocationExecution(audit, "cleanup"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingResult.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
            Assert.That(result.Value, Is.Zero);
            Assert.That(events.Events.Single(e => e.Outcome == SecurityEventOutcomes.Success).Properties,
                Does.ContainKey("revoked").WithValue("false").And.ContainKey("reason").WithValue("cleanup"));
        }
    }

    [Test]
    public async Task ServiceExecutorAllTenantAuditUsesActualUserTenant()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var events = new RecordingSecurityEventSink();
        var repository = new Mock<IUserRepository>();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, TenantId = tenantId, DisplayEmail = "tenant@example.com" });
        var service = CreateService(repository.Object, new RecoveryCodeOptions { CodeCount = 1 }, securityEvents: events);

        var result = await ((IRecoveryCodeMutationExecutor)service).GenerateRecoveryCodesAsync(userId,
            GenerationExecution(new AuditContext(ActorUserId: userId), tenant: null, includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(events.Events.Single(e => e.Outcome == SecurityEventOutcomes.Success).TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task ServicePublicRevocationRejectsInvalidProofAndHostDenial()
    {
        var actorId = Guid.NewGuid();
        var proof = CreateProof(actorId);
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        var events = new RecordingSecurityEventSink();
        var repository = new Mock<IUserRepository>();
        repository.Setup(r => r.GetUserByIdAsync(actorId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = actorId, DisplayEmail = "test@example.com" });
        var service = CreateService(repository.Object, new RecoveryCodeOptions(), securityEvents: events,
            authorizer: authorizer.Object);
        var wrongSession = new RevokeRecoveryCodesRequest(actorId,
            new AccountSecurityActorContext(actorId, TenantContext.Global, Guid.NewGuid(), proof,
                new AuditContext(ActorUserId: actorId)), TenantContext.Global);

        var proofFailure = await service.RevokeRecoveryCodesAsync(wrongSession);
        var denied = await service.RevokeRecoveryCodesAsync(CreateRevocationRequest(actorId, proof));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(proofFailure.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(denied.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(events.Events.Count(e => e.Outcome == SecurityEventOutcomes.Failure), Is.EqualTo(2));
        }
        authorizer.Verify(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ServicePublicGenerationRejectsActorProofMismatchAndAllTenantDenial()
    {
        var actorId = Guid.NewGuid();
        var mismatchedProof = CreateProof(Guid.NewGuid());
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        var events = new RecordingSecurityEventSink();
        var service = CreateService(Mock.Of<IUserRepository>(), new RecoveryCodeOptions { CodeCount = 1 },
            securityEvents: events, authorizer: authorizer.Object);
        var mismatch = new RecoveryCodeGenerationRequest(actorId,
            new AccountSecurityActorContext(actorId, TenantContext.Global, mismatchedProof.SessionId, mismatchedProof,
                new AuditContext(ActorUserId: actorId)), TenantContext.Global,
            settings: new RecoveryCodeGenerationSettings(CodeCount: 1));
        var validProof = CreateProof(actorId);
        var missingAuditActor = new RecoveryCodeGenerationRequest(actorId,
            new AccountSecurityActorContext(actorId, TenantContext.Global, validProof.SessionId, validProof,
                new AuditContext()), TenantContext.Global,
            settings: new RecoveryCodeGenerationSettings(CodeCount: 1));

        var proofFailure = await service.GenerateRecoveryCodesAsync(mismatch);
        var purposeFailure = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId,
            new FreshMfaVerificationProof(actorId, null, Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), "totp-management")));
        var auditFailure = await service.GenerateRecoveryCodesAsync(missingAuditActor);
        var denied = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, validProof,
            includeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(proofFailure.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(purposeFailure.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(auditFailure.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(denied.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(events.Events.Count(e => e.Outcome == SecurityEventOutcomes.Failure && e.TenantId == null &&
                e.Properties?.GetValueOrDefault("scope") == "all_tenants"), Is.EqualTo(1));
        }
        authorizer.Verify(a => a.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task PublicMutationsShouldSanitizeAuditActorMismatchWithoutMutation()
    {
        var actorId = Guid.NewGuid();
        var proof = CreateProof(actorId);
        var unsafeAudit = new AuditContext(Guid.NewGuid(), "untrusted-ip", "untrusted-agent", "untrusted-correlation",
            new Dictionary<string, string> { ["untrusted"] = "value" });
        var events = new RecordingSecurityEventSink();
        var credentials = new Mock<ICredentialRepository>();
        var service = CreateService(Mock.Of<IUserRepository>(), new RecoveryCodeOptions(), credentials: credentials.Object,
            securityEvents: events);

        var generation = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(actorId, proof, audit: unsafeAudit));
        var revocation = await service.RevokeRecoveryCodesAsync(CreateRevocationRequest(actorId, proof, audit: unsafeAudit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(generation.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(revocation.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            foreach (var eventType in new[] { AshlarSecurityEventTypes.RecoveryCodesGenerated, AshlarSecurityEventTypes.RecoveryCodesRevoked })
                Assert.That(events.Events.Count(e => e.EventType == eventType && e.Outcome == SecurityEventOutcomes.Failure &&
                    e.ActorUserId == actorId && e.IpAddress == null && e.UserAgent == null && e.CorrelationId == null), Is.EqualTo(1));
        }
        credentials.VerifyNoOtherCalls();
    }

    [Test]
    public async Task ServiceExecutorCoversAuditTenantAndNullReasonVariants()
    {
        var userId = Guid.NewGuid();
        var audit = new AuditContext(ActorUserId: userId);
        var events = new RecordingSecurityEventSink();
        var nonTenantUser = new Mock<IUser>();
        nonTenantUser.SetupGet(user => user.Id).Returns(userId);
        nonTenantUser.SetupGet(user => user.DisplayEmail).Returns("global@example.com");
        var repository = new Mock<IUserRepository>();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>())).ReturnsAsync(nonTenantUser.Object);
        var credentials = new Mock<ICredentialRepository>();
        credentials.Setup(r => r.RevokeCredentialsAsync(userId, ProviderType.RecoveryCode, "RecoveryCode", It.IsAny<CancellationToken>())).ReturnsAsync(1);
        var service = CreateService(repository.Object, new RecoveryCodeOptions { CodeCount = 1, ExpiresAfter = null },
            credentials.Object, securityEvents: events);
        var executor = (IRecoveryCodeMutationExecutor)service;

        var generated = await executor.GenerateRecoveryCodesAsync(userId,
            GenerationExecution(audit, tenant: null, includeAllTenants: true));
        var revoked = await executor.RevokeRecoveryCodesAsync(userId, RevocationExecution(audit));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(generated.Succeeded, Is.True);
            Assert.That(revoked.Value, Is.EqualTo(1));
            Assert.That(events.Events.Where(e => e.Outcome == SecurityEventOutcomes.Success), Has.All.Property("TenantId").Null);
            Assert.That(events.Events.Single(e => e.EventType == AshlarSecurityEventTypes.RecoveryCodesRevoked).Properties,
                Does.Not.ContainKey("reason").And.ContainKey("revoked").WithValue("true"));
        }
    }

    [Test]
    public async Task ServiceExecutorGenerationUsesExplicitExpiryAndCommittedNotificationContext()
    {
        var userId = Guid.NewGuid();
        var audit = new AuditContext(ActorUserId: userId, IpAddress: "203.0.113.50",
            UserAgent: "recovery-agent", CorrelationId: "recovery-correlation");
        var repository = new Mock<IUserRepository>();
        repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "test@example.com" });
        var credentials = new Mock<ICredentialRepository>();
        var transactions = new Mock<IAshlarTransactionProvider>();
        var transaction = new Mock<IAshlarTransaction>();
        var committed = new List<Func<CancellationToken, Task>>();
        transaction.Setup(t => t.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()))
            .Callback<Func<CancellationToken, Task>>(committed.Add);
        transaction.Setup(t => t.CommitAsync(It.IsAny<CancellationToken>())).Returns<CancellationToken>(async cancellationToken =>
        {
            foreach (var callback in committed) await callback(cancellationToken);
        });
        transactions.Setup(t => t.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);
        var notifications = new Mock<ISecurityNotificationService>();
        var composition = DurableSecurityMutationTestComposition.Compose(transactions.Object, new NullSecurityEventSink(), repository.Object, credentials.Object);
        var service = new RecoveryCodeService(repository.Object, credentials.Object, composition.Transactions,
            new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(
                Options.Create(new RecoveryCodeOptions { CodeCount = 1, ExpiresAfter = TimeSpan.FromDays(30) }),
                securityEventSink: composition.Events,
                notificationService: notifications.Object));
        var request = new RecoveryCodeGenerationExecutionRequest(audit, TenantContext.Global, false, null,
            true, 1, TimeSpan.FromHours(1));

        var result = await ((IRecoveryCodeMutationExecutor)service).GenerateRecoveryCodesAsync(userId, request);

        Assert.That(result.Succeeded, Is.True);
        credentials.Verify(r => r.CreateCredentialAsync(It.Is<UserCredential>(credential =>
            credential.ExpiresAt > credential.CreatedAt && credential.ExpiresAt <= credential.CreatedAt.AddHours(1)),
            It.IsAny<CancellationToken>()), Times.Once);
        notifications.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.IpAddress == audit.IpAddress && notification.UserAgent == audit.UserAgent),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void ServicePublicSurfaceHasNoRawTargetMutationOverloads()
    {
        var mutationMethods = typeof(IRecoveryCodeService).GetMethods();

        Assert.That(mutationMethods, Has.All.Matches<System.Reflection.MethodInfo>(method =>
            method.GetParameters().Length > 0 && method.GetParameters()[0].ParameterType != typeof(Guid)));
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
        var composition = new DurableSecurityMutationTestComposition(participants: [repository.Object, credentialRepository.Object]);
        var credentialService = new CredentialService(
            repository.Object,
            credentialRepository.Object,
            Mock.Of<ISecretProtector>(),
            composition.Transactions,
            new CredentialServiceDependencies(SecurityEventSink: composition.Events));
        var pipeline = new AuthenticationPipeline(
            registry,
            credentialService,
            composition.Transactions,
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
        services.AddAshlarProviderScoped(_ => new Mock<IUserRepository>().Object);
        services.AddAshlarProviderScoped(_ => new Mock<ICredentialRepository>().Object);
        services.AddAshlarProviderScoped(_ => new Mock<IAuthenticationSessionRepository>().Object);
        services.AddSingleton<IAccountSecurityOperationAuthorizer, AllowAllAccountSecurityOperationAuthorizer>();
        services.AddAshlarRecoveryCodes(opts =>
        {
            opts.CodeCount = 12;
        });
        services.AddDurableAuditForTests();

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
        var credentialService = new TestCredentialService();
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
        credentialService.ContextResolveResult = (user, null, null, false);

        // Setup: AuthenticateAsync returns SUCCESS but requests consumption
        provider.Setup(p => p.AuthenticateAsync(assertion, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResult(AuthenticationResultStatus.Succeeded, IsCredentialConsumed: true));

        var pipeline = new AuthenticationPipeline(
            providerRegistry.Object,
            credentialService,
            AshlarDurableTransactionProvider.Create(transProvider.Object),
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

    private RecoveryCodeService CreateServiceForGenerationValidation(
        RecoveryCodeOptions options,
        Guid? userTenantId = null,
        IAccountSecurityOperationAuthorizer? authorizer = null,
        ISecurityEventSink? securityEventSink = null,
        ICredentialRepository? credentialRepository = null)
    {
        var repository = new Mock<IUserRepository>();
        var credentials = credentialRepository ?? new Mock<ICredentialRepository>().Object;
        var transactionProvider = new RecordingTransactionProvider();

        repository.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => new User { Id = id, DisplayEmail = "test@example.com", AccountState = UserAccountState.Active, TenantId = userTenantId });

        var composition = DurableSecurityMutationTestComposition.Create(
            transactionProvider,
            securityEventSink ?? new NullSecurityEventSink(),
            repository.Object,
            credentials);
        return new RecoveryCodeService(repository.Object, credentials, composition.Transactions, new PasswordHasherSelector([new PasswordHasherV1()]), CreateDependencies(Options.Create(options), securityEventSink:
            composition.Events, authorizer: authorizer));
    }

    private RecoveryCodeServiceDependencies CreateDependencies(
        IOptions<RecoveryCodeOptions> options,
        TimeProvider? timeProvider = null,
        SecurityEventFanOutSink? securityEventSink = null,
        ISecurityNotificationService? notificationService = null,
        IAccountSecurityOperationAuthorizer? authorizer = null)
    {
        return new RecoveryCodeServiceDependencies(options, ProofValidator(timeProvider), timeProvider, securityEventSink, notificationService,
            authorizer ?? new AllowAllAccountSecurityOperationAuthorizer());
    }

    private readonly Dictionary<Guid, AuthenticationSession> _proofSessions = [];

    private ActiveSessionFreshProofValidator ProofValidator(TimeProvider? timeProvider)
    {
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(r => r.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => _proofSessions.GetValueOrDefault(id));
        return new(sessions.Object, timeProvider ?? TimeProvider.System);
    }

    private static RecoveryCodeGenerationRequest CreateGenerationRequest(
        Guid actorId,
        FreshMfaVerificationProof proof,
        Guid? targetId = null,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        AuditContext? audit = null,
        int? codeCount = 1,
        TimeSpan? expiresAfter = null) =>
        new(targetId ?? actorId,
            new AccountSecurityActorContext(actorId, tenant ?? TenantContext.Global, proof.SessionId, proof,
                audit ?? new AuditContext(ActorUserId: actorId)),
            includeAllTenants ? null : tenant ?? TenantContext.Global,
            includeAllTenants, settings: new RecoveryCodeGenerationSettings(CodeCount: codeCount, ExpiresAfter: expiresAfter));

    private static RevokeRecoveryCodesRequest CreateRevocationRequest(
        Guid actorId,
        FreshMfaVerificationProof proof,
        Guid? targetId = null,
        TenantContext? tenant = null,
        bool includeAllTenants = false,
        AuditContext? audit = null,
        string? reason = null) =>
        new(targetId ?? actorId,
            new AccountSecurityActorContext(actorId, tenant ?? TenantContext.Global, proof.SessionId, proof,
                audit ?? new AuditContext(ActorUserId: actorId)),
            includeAllTenants ? null : tenant ?? TenantContext.Global,
            includeAllTenants, reason);

    private static RecoveryCodeGenerationExecutionRequest GenerationExecution(
        AuditContext audit,
        bool replaceExisting = true,
        TenantContext? tenant = null,
        bool includeAllTenants = false) =>
        new(audit, includeAllTenants ? null : tenant ?? TenantContext.Global, includeAllTenants, null,
            replaceExisting, null, null);

    private static RevokeRecoveryCodesExecutionRequest RevocationExecution(AuditContext audit, string? reason = null) =>
        new(audit, TenantContext.Global, false, reason);

    private RecoveryCodeService CreateService(
        IUserRepository repository,
        RecoveryCodeOptions options,
        ICredentialRepository? credentials = null,
        ISecurityEventSink? securityEvents = null,
        IAccountSecurityOperationAuthorizer? authorizer = null)
    {
        credentials ??= Mock.Of<ICredentialRepository>();
        var composition = new DurableSecurityMutationTestComposition(
            securityEvents ?? new NullSecurityEventSink(), repository, credentials);

        return new RecoveryCodeService(repository, credentials, composition.Transactions,
            new PasswordHasherSelector([new PasswordHasherV1()]),
            CreateDependencies(Options.Create(options), securityEventSink: composition.Events, authorizer: authorizer));
    }

    private FreshMfaVerificationProof CreateProof(Guid userId, TenantContext? tenant = null, DateTimeOffset? expiresAt = null)
    {
        var verifiedAt = DateTimeOffset.UtcNow;
        var proof = new FreshMfaVerificationProof(userId, tenant?.TenantId, Guid.NewGuid(), verifiedAt, expiresAt ?? verifiedAt.AddMinutes(10), RecoveryCodeService.ProofPurpose);
        _proofSessions[proof.SessionId] = new AuthenticationSession
        {
            Id = proof.SessionId,
            UserId = userId,
            TenantId = tenant?.TenantId,
            TokenHash = "hash",
            CreatedAt = verifiedAt,
            AuthenticatedAt = verifiedAt,
            ExpiresAt = verifiedAt.AddHours(1)
        };
        return proof;
    }

    [Test]
    public async Task ManagementShouldRejectProofAfterSourceSessionRevocation()
    {
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);
        _proofSessions[proof.SessionId].RevokedAt = DateTimeOffset.UtcNow;
        var credentials = new Mock<ICredentialRepository>();
        var service = CreateServiceForGenerationValidation(new RecoveryCodeOptions { CodeCount = 1 }, credentialRepository: credentials.Object);

        var generated = await service.GenerateRecoveryCodesAsync(CreateGenerationRequest(userId, proof));
        var revoked = await service.RevokeRecoveryCodesAsync(CreateRevocationRequest(userId, proof));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(generated.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(revoked.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
        credentials.Verify(r => r.AcquireUserMutationLockAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.CreateCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()), Times.Never);
        credentials.Verify(r => r.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
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

    private sealed class AllowAllAccountSecurityOperationAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(true);
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
