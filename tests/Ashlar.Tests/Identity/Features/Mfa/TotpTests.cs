using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Mfa;

[TestFixture]
internal sealed class TotpTests
{
    private Mock<IUserRepository> _repository = null!;
    private Mock<ICredentialRepository> _credentialRepository = null!;
    private TestCredentialService _credentialService = null!;
    private AshlarDurableTransactionProvider _transactionProvider = null!;
    private SecurityEventFanOutSink _durableEvents = null!;
    private Mock<IAshlarTransactionProvider> _rawTransactionProvider = null!;
    private Mock<IAshlarTransaction> _transaction = null!;
    private Mock<ISecurityEventSink> _securityEvents = null!;
    private Mock<IAuthenticationSessionRepository> _sessionRepository = null!;
    private FakeTimeProvider _timeProvider = null!;
    private TotpOptions _options = null!;

    [SetUp]
    public void SetUp()
    {
        _repository = new Mock<IUserRepository>();
        _credentialRepository = new Mock<ICredentialRepository>();
        _credentialService = new TestCredentialService();
        _rawTransactionProvider = new Mock<IAshlarTransactionProvider>();
        _transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
        _securityEvents = new Mock<ISecurityEventSink>();
        _sessionRepository = new Mock<IAuthenticationSessionRepository>();
        _timeProvider = new FakeTimeProvider();
        _options = new TotpOptions();

        _rawTransactionProvider.Setup(x => x.BeginTransactionAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(_transaction.Object);
        var composition = DurableSecurityMutationTestComposition.Compose(
            _rawTransactionProvider.Object,
            _securityEvents.Object,
            _repository.Object,
            _credentialRepository.Object);
        _transactionProvider = composition.Transactions;
        _durableEvents = composition.Events;
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
        _credentialRepository.Setup(x => x.ListCredentialsForUserAsync(It.IsAny<Guid>(), true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<UserCredential>());
        _repository.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid userId, CancellationToken _) => new User { Id = userId, DisplayEmail = "user@example.com" });
    }

    private TotpService CreateService(IAccountSecurityOperationAuthorizer? authorizer = null)
    {
        return new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService,
            _transactionProvider,
            [CreateProvider()],
            authorizer ?? CreateAuthorizer(),
            new TotpServiceDependencies(Options.Create(_options), ProofValidator(), _timeProvider,
                _durableEvents));
    }

    private TotpAuthenticationProvider CreateProvider()
    {
        return new TotpAuthenticationProvider(
            Options.Create(_options),
            _timeProvider);
    }

    private TotpService CreateServiceWithRecoveryCodeProvider()
    {
        var recoveryProvider = new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
        return new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService,
            _transactionProvider,
            [CreateProvider(), CreateSecondaryProvider(recoveryProvider)],
            CreateAuthorizer(),
            new TotpServiceDependencies(Options.Create(_options), ProofValidator(), _timeProvider,
                _durableEvents));
    }

    private static ISecondaryAuthenticationFactorProvider CreateSecondaryProvider(AuthenticationProviderKey providerKey)
    {
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns(providerKey.Name);
        return provider.Object;
    }

    private static IAccountSecurityOperationAuthorizer CreateAuthorizer()
    {
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(x => x.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        return authorizer.Object;
    }

    private FreshMfaVerificationProof CreateProof(Guid userId, TenantContext? tenant = null, DateTimeOffset? expiresAt = null)
    {
        var verifiedAt = DateTimeOffset.UtcNow;
        if (expiresAt.HasValue)
        {
            var proof = new FreshMfaVerificationProof(userId, tenant?.TenantId, Guid.NewGuid(), verifiedAt, expiresAt.Value, TotpService.ProofPurpose);
            RegisterSession(proof.SessionId, userId, tenant, verifiedAt);
            return proof;
        }

        var session = CreateFreshSession(userId, tenant, verifiedAt);
        var result = new StepUpAuthenticationService(new FakeTimeProvider(verifiedAt))
            .CreateFreshMfaProof(new ValidatedAuthenticationSession(session), new StepUpRequirement(TimeSpan.FromMinutes(10), Purpose: TotpService.ProofPurpose)).Value!;
        RegisterSession(result.SessionId, userId, tenant, verifiedAt);
        return result;
    }

    private FreshPrimaryAuthenticationProof CreatePrimaryProof(Guid userId, TenantContext? tenant = null, DateTimeOffset? expiresAt = null)
    {
        var authenticatedAt = DateTimeOffset.UtcNow;
        if (expiresAt.HasValue)
        {
            var proof = new FreshPrimaryAuthenticationProof(userId, tenant?.TenantId, Guid.NewGuid(), authenticatedAt, expiresAt.Value, TotpService.ProofPurpose);
            RegisterSession(proof.SessionId, userId, tenant, authenticatedAt);
            return proof;
        }

        var session = CreateFreshSession(userId, tenant, authenticatedAt);
        var result = new StepUpAuthenticationService(new FakeTimeProvider(authenticatedAt))
            .CreateFreshPrimaryAuthenticationProof(new ValidatedAuthenticationSession(session), TimeSpan.FromMinutes(10), TotpService.ProofPurpose).Value!;
        RegisterSession(result.SessionId, userId, tenant, authenticatedAt);
        return result;
    }

    private ActiveSessionFreshProofValidator ProofValidator() => new(_sessionRepository.Object, _timeProvider);

    private void RegisterSession(Guid sessionId, Guid userId, TenantContext? tenant, DateTimeOffset now) =>
        _sessionRepository.Setup(r => r.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = tenant?.TenantId,
            TokenHash = "hash",
            CreatedAt = now,
            AuthenticatedAt = now,
            ExpiresAt = now.AddHours(1)
        });

    [Test]
    public async Task ManagementShouldRejectProofsAfterSourceSessionRevocation()
    {
        var userId = Guid.NewGuid();
        var primary = CreatePrimaryProof(userId);
        var mfa = CreateProof(userId);
        RevokeSession(primary.SessionId, userId);
        RevokeSession(mfa.SessionId, userId);
        var service = CreateService();

        var start = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartEnrollmentAsync(
            new StartTotpEnrollmentRequest(userId, "issuer", "account")
            {
                FreshPrimaryAuthenticationProof = primary,
                CurrentSessionId = primary.SessionId,
                Audit = new AuditContext(userId)
            }));
        var complete = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = primary,
            CurrentSessionId = primary.SessionId,
            Audit = new AuditContext(userId)
        });
        var disabled = await service.DisableAsync(new DisableTotpRequest(userId, TenantContext.Global, mfa.SessionId, mfa, new AuditContext(userId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(start!.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(complete.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(disabled, Is.False);
        }
        _credentialRepository.Verify(r => r.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.That(_credentialService.LinkCalls, Is.Empty);
    }

    private void RevokeSession(Guid sessionId, Guid userId) =>
        _sessionRepository.Setup(r => r.GetSessionAsync(sessionId, It.IsAny<CancellationToken>())).ReturnsAsync(new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = _timeProvider.GetUtcNow().AddMinutes(-1),
            AuthenticatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddHours(1),
            RevokedAt = _timeProvider.GetUtcNow()
        });

    private static AuthenticationSession CreateFreshSession(Guid userId, TenantContext? tenant, DateTimeOffset now) => new()
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        TenantId = tenant?.TenantId,
        TokenHash = "hash",
        CreatedAt = now,
        AuthenticatedAt = now,
        AdditionalVerificationAt = now,
        ExpiresAt = now.AddHours(1)
    };

    private void SetupExistingTotp(Guid userId)
    {
        var credential = CreateCredential(userId, _options.ProviderKey);
        _credentialRepository
            .Setup(x => x.GetCredentialForUserAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        _credentialRepository.Setup(x => x.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([credential]);
    }

    private void SetupExistingRecoveryCode(Guid userId)
    {
        var providerKey = new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
        var credential = CreateCredential(userId, providerKey);
        _credentialRepository.Setup(x => x.ListCredentialsForUserAsync(userId, true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([credential]);
    }

    private UserCredential CreateCredential(Guid userId, AuthenticationProviderKey providerKey)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = providerKey.Type,
            ProviderName = providerKey.Name,
            ProviderKey = providerKey.Name,
            Version = "v1",
            CreatedAt = _timeProvider.GetUtcNow(),
            Status = CredentialStatus.Active
        };
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
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(ITotpService)), Is.True);
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
    public void AssertionConstructorThrowsOnInvalidCode()
    {
        Assert.Throws<ArgumentException>(() => _ = new TotpAssertion(" "));
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
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(ITotpService)), Has.Exactly(1).Items);
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
            Assert.That(new TotpAssertion("123456").ProviderIdentity, Is.EqualTo(TotpOptions.DefaultProviderKey));
            Assert.That(new TotpAssertion("123456", providerKey: providerKey).ProviderIdentity, Is.EqualTo(providerKey));
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
        var deps = new TotpServiceDependencies(Options.Create(_options), ProofValidator(), securityEventSink:
            _durableEvents);
        var authorizer = CreateAuthorizer();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(null!, _credentialRepository.Object, _credentialService, _transactionProvider, [provider], authorizer, deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, null!, _credentialService, _transactionProvider, [provider], authorizer, deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, null!, _transactionProvider, [provider], authorizer, deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService, null!, [provider], authorizer, deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService, _transactionProvider, [provider], null!, deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService, _transactionProvider, [provider], authorizer, null!));
            Assert.Throws<InvalidOperationException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService, _transactionProvider, [], authorizer, deps));
        }
    }

    [Test]
    public void TotpServiceConstructorAllowsDefaultTimeProvider()
    {
        Assert.DoesNotThrow(() => _ = new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService,
            _transactionProvider,
            [CreateProvider()],
            CreateAuthorizer(),
            new TotpServiceDependencies(Options.Create(_options), ProofValidator(), securityEventSink:
                _durableEvents)));
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
    public async Task StartEnrollmentAsyncShouldAcceptMatchingFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);
        SetupExistingTotp(userId);

        var enrollment = await service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(enrollment.SharedSecret, Is.Not.Empty);
            Assert.That(enrollment.AuthenticatorUri, Does.Contain("otpauth://totp/Ashlar:user%40example.com"));
        }
    }

    [Test]
    public async Task StartEnrollmentAsyncShouldAcceptFreshPrimaryProofForFirstTotp()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var proof = CreatePrimaryProof(userId);

        var enrollment = await service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        Assert.That(enrollment.SharedSecret, Is.Not.Empty);
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectFreshPrimaryProofWhenAnotherMfaFactorExists()
    {
        var service = CreateServiceWithRecoveryCodeProvider();
        var userId = Guid.NewGuid();
        var proof = CreatePrimaryProof(userId);
        SetupExistingRecoveryCode(userId);

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
            {
                FreshPrimaryAuthenticationProof = proof,
                CurrentSessionId = proof.SessionId
            }));

        Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public async Task StartEnrollmentAsyncShouldAcceptFreshMfaProofWhenAnotherMfaFactorExists()
    {
        var service = CreateServiceWithRecoveryCodeProvider();
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);
        SetupExistingRecoveryCode(userId);

        var enrollment = await service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId
        });

        Assert.That(enrollment.SharedSecret, Is.Not.Empty);
    }

    [Test]
    public async Task StartEnrollmentAsyncShouldAcceptTenantScopedFreshPrimaryProofForFirstTotp()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var proof = CreatePrimaryProof(userId, tenant);
        _repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = tenant.TenantId });

        var enrollment = await service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId,
            Tenant = tenant
        });

        Assert.That(enrollment.SharedSecret, Is.Not.Empty);
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectMissingFreshPrimaryProofForFirstTotp()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")));

        Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectMissingFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        SetupExistingTotp(userId);

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            _repository.Verify(x => x.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectProofForAnotherUserOrTenant()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        SetupExistingTotp(userId);

        var wrongUser = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
            {
                FreshMfaProof = CreateProof(Guid.NewGuid(), tenant),
                Tenant = tenant
            }));
        var wrongTenant = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
            {
                FreshMfaProof = CreateProof(userId, new TenantContext(Guid.NewGuid())),
                Tenant = tenant
            }));
        var wrongPurpose = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
            {
                FreshMfaProof = new FreshMfaVerificationProof(userId, tenant.TenantId, Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5), "recovery-code-management"),
                Tenant = tenant
            }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongUser?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(wrongTenant?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(wrongPurpose?.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectMissingActorBeforeReturningSecret()
    {
        var service = CreateService();

        var exception = Assert.ThrowsAsync<ArgumentException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(Guid.Empty, "Ashlar", "user@example.com")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.ParamName, Is.EqualTo("request.ActorUserId"));
            _repository.Verify(x => x.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
            _securityEvents.Verify(x => x.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldAcceptMatchingFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        var proof = CreateProof(userId, tenant);
        _repository.Setup(x => x.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com", TenantId = tenant.TenantId });
        SetupExistingTotp(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, secret, code)
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId,
            Tenant = tenant,
            Audit = new AuditContext(userId)
        });

        Assert.That(result.Succeeded && _credentialService.LinkCalls.Single().TenantId == tenant.TenantId, Is.True);
        _credentialRepository.Verify(x => x.AcquireUserMutationLockAsync(userId, It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldAcceptFreshPrimaryProofForFirstTotp()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);
        var proof = CreatePrimaryProof(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, secret, code)
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectMismatchedFreshPrimaryProofForFirstTotp()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var tenantUserId = Guid.NewGuid();
        _repository.Setup(r => r.GetUserByIdAsync(tenantUserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = tenantUserId, DisplayEmail = "tenant@example.com", TenantId = tenant.TenantId });

        var missing = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456"));
        var wrongUser = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(Guid.NewGuid())
        });
        var wrongTenant = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(userId, tenant)
        });
        var globalProofForTenantRequest = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(tenantUserId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(tenantUserId),
            Tenant = tenant
        });
        var wrongSession = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = CreatePrimaryProof(userId),
            CurrentSessionId = Guid.NewGuid()
        });
        var expiredProof = CreatePrimaryProof(userId, expiresAt: _timeProvider.GetUtcNow().AddSeconds(-1));
        var expired = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = expiredProof,
            CurrentSessionId = expiredProof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(wrongUser.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(wrongTenant.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(globalProofForTenantRequest.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(wrongSession.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(expired.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectMissingOrMismatchedFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        SetupExistingTotp(userId);

        var missing = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456"));
        var mismatched = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
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
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectPrimaryProofWhenReplacingExistingTotp()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var proof = CreatePrimaryProof(userId);
        SetupExistingTotp(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectPrimaryProofWhenAnotherMfaFactorExists()
    {
        var service = CreateServiceWithRecoveryCodeProvider();
        var userId = Guid.NewGuid();
        var proof = CreatePrimaryProof(userId);
        SetupExistingRecoveryCode(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectExpiredFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId, expiresAt: _timeProvider.GetUtcNow().AddSeconds(-1));
        SetupExistingTotp(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId
        });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectProofForAnotherSession()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);
        SetupExistingTotp(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")
        {
            FreshMfaProof = proof,
            CurrentSessionId = Guid.NewGuid()
        });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectGlobalProofForAnotherUser()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        SetupExistingTotp(userId);

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
            {
                FreshMfaProof = CreateProof(Guid.NewGuid())
            }));

        Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public void StartEnrollmentAsyncShouldRejectTenantProofForGlobalRequest()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        SetupExistingTotp(userId);

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() =>
            service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")
            {
                FreshMfaProof = CreateProof(userId, new TenantContext(Guid.NewGuid()))
            }));

        Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
    }

    [Test]
    public void CompleteEnrollmentAsyncShouldRejectMissingActorBeforeReplacingCredential()
    {
        var service = CreateService();

        var exception = Assert.ThrowsAsync<ArgumentException>(() =>
            service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(Guid.Empty, "secret", "123456")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.ParamName, Is.EqualTo("request.ActorUserId"));
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            Assert.That(_credentialService.LinkCalls, Is.Empty);
            _securityEvents.Verify(x => x.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task DisableAsyncShouldRejectMissingOrMismatchedFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());

        var missing = await service.DisableAsync(new DisableTotpRequest(userId));
        var mismatched = await service.DisableAsync(new DisableTotpRequest(userId)
        {
            FreshMfaProof = CreateProof(userId, new TenantContext(Guid.NewGuid())),
            Tenant = tenant
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missing, Is.False);
            Assert.That(mismatched, Is.False);
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task DisableAsyncShouldAcceptMatchingFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var proof = CreateProof(userId);

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        var result = await service.DisableAsync(new DisableTotpRequest(userId)
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId,
            Audit = new AuditContext(userId)
        });

        Assert.That(result, Is.True);
    }

    [Test]
    public void DisableAsyncShouldRejectMissingActorBeforeRevokingCredential()
    {
        var service = CreateService();

        var exception = Assert.ThrowsAsync<ArgumentException>(() =>
            service.DisableAsync(new DisableTotpRequest(Guid.Empty)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.ParamName, Is.EqualTo("request.ActorUserId"));
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _securityEvents.Verify(x => x.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void PublicTotpRequestsRequireActorScopeSessionAuditAndExactlyOneProof()
    {
        var actor = Guid.NewGuid();
        var session = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var audit = new AuditContext(actor);
        var mfa = new FreshMfaVerificationProof(actor, tenant.TenantId, session, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5));
        var primary = new FreshPrimaryAuthenticationProof(actor, tenant.TenantId, session, _timeProvider.GetUtcNow(), _timeProvider.GetUtcNow().AddMinutes(5));

        var start = new StartTotpEnrollmentRequest(
            new TotpEnrollmentVerificationContext(actor, tenant, session, audit, freshMfaProof: mfa), "Ashlar", "user@example.com");
        var verify = new VerifyTotpEnrollmentRequest(
            new TotpEnrollmentVerificationContext(actor, tenant, session, audit, freshPrimaryAuthenticationProof: primary), "secret", "123456");
        var disable = new DisableTotpRequest(actor, tenant, session, mfa, audit);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(start.FreshMfaProof, Is.SameAs(mfa));
            Assert.That(verify.FreshPrimaryAuthenticationProof, Is.SameAs(primary));
            Assert.That(disable.FreshMfaProof, Is.SameAs(mfa));
            Assert.Throws<ArgumentException>(() => _ = new TotpEnrollmentVerificationContext(Guid.Empty, tenant, session, audit, freshMfaProof: mfa));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpEnrollmentVerificationContext(actor, null!, session, audit, freshMfaProof: mfa));
            Assert.Throws<ArgumentException>(() => _ = new TotpEnrollmentVerificationContext(actor, tenant, Guid.Empty, audit, freshMfaProof: mfa));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpEnrollmentVerificationContext(actor, tenant, session, null!, freshMfaProof: mfa));
            Assert.Throws<ArgumentException>(() => _ = new TotpEnrollmentVerificationContext(actor, tenant, session, new AuditContext(Guid.NewGuid()), freshMfaProof: mfa));
            Assert.Throws<ArgumentException>(() => _ = new TotpEnrollmentVerificationContext(actor, tenant, session, new AuditContext(), freshMfaProof: mfa));
            Assert.Throws<ArgumentException>(() => _ = new TotpEnrollmentVerificationContext(actor, tenant, session, audit));
            Assert.Throws<ArgumentException>(() => _ = new TotpEnrollmentVerificationContext(actor, tenant, session, audit, mfa, primary));
            Assert.Throws<ArgumentNullException>(() => _ = new StartTotpEnrollmentRequest(null!, "i", "a"));
            Assert.Throws<ArgumentNullException>(() => _ = new VerifyTotpEnrollmentRequest(null!, "s", "c"));
            Assert.Throws<ArgumentNullException>(() => _ = new DisableTotpRequest(actor, tenant, session, null!, audit));
        }
    }

    [Test]
    public void TotpServiceRejectsAuditWithoutActorAndNullOptions()
    {
        var actor = Guid.NewGuid();
        var proof = CreatePrimaryProof(actor);
        var exception = Assert.ThrowsAsync<ArgumentException>(() => CreateService().StartEnrollmentAsync(
            new StartTotpEnrollmentRequest(actor, "i", "a")
            {
                Audit = new AuditContext(),
                FreshPrimaryAuthenticationProof = proof,
                CurrentSessionId = proof.SessionId
            }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.ParamName, Is.EqualTo("request.audit"));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpServiceDependencies(null!, ProofValidator()));
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncCoversInputAndTenantFailuresWithoutMutation()
    {
        var service = CreateService();
        var actor = Guid.NewGuid();
        var proof = CreatePrimaryProof(actor);

        var emptyCode = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, "secret", " "));
        var emptySecret = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, " ", "123456"));
        var longSecret = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, new string('A', 257), "123456"));
        _repository.Setup(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);
        var missingUser = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(emptyCode.FailureCode, Is.EqualTo(AshlarFailureCodes.EmptyCode));
            Assert.That(emptySecret.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
            Assert.That(longSecret.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
            Assert.That(missingUser.Succeeded, Is.False);
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncCoversInvalidSecretAndCode()
    {
        var service = CreateService();
        var actor = Guid.NewGuid();
        var proof = CreatePrimaryProof(actor);

        var malformed = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, "!", "123456")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });
        var shortSecret = Base32.Encode(new byte[15]);
        _ = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, shortSecret, "123456")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });
        var secret = Base32.Encode(new byte[20]);
        var invalidCode = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, secret, "999999")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(malformed.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecretFormat));
            Assert.That(invalidCode.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCode));
        }
    }

    [Test]
    public async Task TotpMutationsRejectHostAuthorization()
    {
        var authorizer = new Mock<IAccountSecurityOperationAuthorizer>();
        authorizer.Setup(x => x.AuthorizeAsync(It.IsAny<AccountSecurityAuthorizationContext>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);
        var service = CreateService(authorizer.Object);
        var actor = Guid.NewGuid();
        var primary = CreatePrimaryProof(actor);
        var mfa = CreateProof(actor);

        var start = Assert.ThrowsAsync<AshlarOperationException>(() => service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(actor, "i", "a")
        {
            FreshPrimaryAuthenticationProof = primary,
            CurrentSessionId = primary.SessionId
        }));
        var complete = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = primary,
            CurrentSessionId = primary.SessionId
        });
        var disable = await service.DisableAsync(new DisableTotpRequest(actor)
        {
            FreshMfaProof = mfa,
            CurrentSessionId = mfa.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(start?.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(complete.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(disable, Is.False);
            foreach (var eventType in new[] { AshlarSecurityEventTypes.TotpEnrollmentStarted,
                         AshlarSecurityEventTypes.TotpEnrollmentCompleted, AshlarSecurityEventTypes.TotpDisabled })
                _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
                    e.EventType == eventType && e.Outcome == SecurityEventOutcomes.Failure && e.UserId == actor &&
                    e.ActorUserId == actor && e.FailureReason == AshlarFailureCodes.ValidationErrorValue &&
                    e.Provider == _options.ProviderKey), It.IsAny<CancellationToken>()), Times.Once);
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(),
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void StartEnrollmentAsyncShouldAuditMissingProofOnceWithoutMutation()
    {
        var actor = Guid.NewGuid();

        Assert.ThrowsAsync<AshlarOperationException>(() => CreateService().StartEnrollmentAsync(
            new StartTotpEnrollmentRequest(actor, "issuer", "account")));

        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.TotpEnrollmentStarted && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actor && e.ActorUserId == actor && e.FailureReason == AshlarFailureCodes.StepUpRequiredValue),
            It.IsAny<CancellationToken>()), Times.Once);
        _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(),
            It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task TotpMutationsShouldAuditInvalidProofOnceWithoutMutation()
    {
        var actor = Guid.NewGuid();
        var expiredAt = _timeProvider.GetUtcNow().AddMinutes(-1);
        var primary = CreatePrimaryProof(actor, expiresAt: expiredAt);
        var mfa = CreateProof(actor, expiresAt: expiredAt);
        var service = CreateService();

        Assert.ThrowsAsync<AshlarOperationException>(() => service.StartEnrollmentAsync(new StartTotpEnrollmentRequest(actor, "issuer", "account")
        {
            FreshPrimaryAuthenticationProof = primary,
            CurrentSessionId = primary.SessionId
        }));
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.TotpEnrollmentStarted && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actor && e.FailureReason == AshlarFailureCodes.StepUpExpiredValue), It.IsAny<CancellationToken>()), Times.Once);

        _securityEvents.Invocations.Clear();
        var complete = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = primary,
            CurrentSessionId = primary.SessionId
        });
        Assert.That(complete.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpExpired));
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.TotpEnrollmentCompleted && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actor && e.FailureReason == AshlarFailureCodes.StepUpExpiredValue), It.IsAny<CancellationToken>()), Times.Once);

        _securityEvents.Invocations.Clear();
        Assert.That(await service.DisableAsync(new DisableTotpRequest(actor)
        {
            FreshMfaProof = mfa,
            CurrentSessionId = mfa.SessionId
        }), Is.False);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.TotpDisabled && e.Outcome == SecurityEventOutcomes.Failure &&
            e.UserId == actor && e.FailureReason == AshlarFailureCodes.StepUpExpiredValue), It.IsAny<CancellationToken>()), Times.Once);
        _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(),
            It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void StartEnrollmentAsyncRejectsMissingScopedUser()
    {
        var actor = Guid.NewGuid();
        var proof = CreatePrimaryProof(actor);
        _repository.Setup(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() => CreateService().StartEnrollmentAsync(
            new StartTotpEnrollmentRequest(actor, "i", "a")
            {
                FreshPrimaryAuthenticationProof = proof,
                CurrentSessionId = proof.SessionId
            }));

        Assert.That(exception?.FailureCode, Is.Not.Null);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncRejectsPostLockScopeLossAndLinkFailures()
    {
        var actor = Guid.NewGuid();
        var user = new User { Id = actor, DisplayEmail = "user@example.com" };
        var proof = CreatePrimaryProof(actor);
        _repository.SetupSequence(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user)
            .ReturnsAsync((IUser?)null);
        var lostScope = await CreateService().CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, "secret", "123456")
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        _repository.Setup(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        var secretBytes = new byte[20];
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);
        _credentialService.LinkResult = Result.Failure(AshlarFailureCodes.LinkFailed, "link failed");
        var detailedFailure = await CreateService().CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(actor, secret, code)
        {
            FreshPrimaryAuthenticationProof = proof,
            CurrentSessionId = proof.SessionId
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(lostScope.Succeeded, Is.False);
            Assert.That(detailedFailure.FailureCode, Is.EqualTo(AshlarFailureCodes.LinkFailed));
        }
    }

    [Test]
    public async Task DisableAsyncCoversMissingUserPostLockScopeLossAndNoCredential()
    {
        var actor = Guid.NewGuid();
        var proof = CreateProof(actor);
        var request = new DisableTotpRequest(actor)
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId
        };
        _repository.Setup(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>())).ReturnsAsync((IUser?)null);
        Assert.That(await CreateService().DisableAsync(request), Is.False);

        var user = new User { Id = actor, DisplayEmail = "user@example.com" };
        _repository.SetupSequence(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user)
            .ReturnsAsync((IUser?)null);
        Assert.That(await CreateService().DisableAsync(request), Is.False);

        _repository.Setup(r => r.GetUserByIdAsync(actor, It.IsAny<CancellationToken>())).ReturnsAsync(user);
        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(actor, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>())).ReturnsAsync(0);
        Assert.That(await CreateService().DisableAsync(request), Is.False);
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
            Assert.Throws<ArgumentNullException>(() => _ = new TotpAuthenticationProvider(null!));
        }
    }

    [Test]
    public void ProviderConstructorAllowsDefaultTimeProvider()
    {
        Assert.DoesNotThrow(() => _ = new TotpAuthenticationProvider(Options.Create(_options)));
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
            Assert.That(provider.FactorType, Is.EqualTo(AuthenticationFactorTypes.Totp));
            Assert.That(provider.CanSatisfyFactor("TOTP"), Is.True);
            Assert.That(provider.CanSatisfyFactor(AuthenticationFactorTypes.RecoveryCode), Is.False);
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

    [TestCase(null)]
    [TestCase("")]
    public async Task ProviderAuthenticateAsyncSucceedsWithMissingMetadata(string? metadata)
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
            Version = "1",
            Metadata = metadata
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion(code), credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
            Assert.That(result.NewMetadata, Does.Contain("LastUsedStep"));
        }
    }

    [TestCase(0)]
    [TestCase(1)]
    public async Task ProviderAuthenticateAsyncFailsOnReplay(int storedStepOffset)
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
            Metadata = $"{{\"LastUsedStep\":{step + storedStepOffset}}}"
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion(code), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task ProviderAuthenticateAsyncSucceedsWithLaterStepAndUpdatesMetadata()
    {
        var provider = CreateProvider();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var currentStep = _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30;
        var code = TotpAuthenticator.GenerateCode(secretBytes, currentStep);

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
            Metadata = $"{{\"LastUsedStep\":{currentStep - 1}}}"
        };

        var result = await provider.AuthenticateAsync(new TotpAssertion(code), credential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
            Assert.That(result.NewMetadata, Is.EqualTo($"{{\"LastUsedStep\":{currentStep}}}"));
            Assert.That(result.CredentialUpdateRequirement, Is.EqualTo(CredentialUpdateRequirement.Required));
        }
    }

    [TestCase("null")]
    [TestCase("{")]
    [TestCase(" ")]
    [TestCase("{}")]
    [TestCase("{\"lastUsedStep\":1}")]
    [TestCase("{\"LastUsedStep\":null}")]
    [TestCase("{\"LastUsedStep\":-1}")]
    [TestCase("{\"LastUsedStep\":\"1\"}")]
    public async Task ProviderAuthenticateAsyncFailsWithMalformedMetadata(string metadata)
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

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
            Assert.That(result.NewMetadata, Is.Null);
            Assert.That(result.CredentialUpdateRequirement, Is.EqualTo(CredentialUpdateRequirement.BestEffort));
        }
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
    public void ProviderShouldUseDefaultCredentialLookup()
    {
        var provider = CreateProvider();

        Assert.That(provider, Is.Not.InstanceOf<IAuthenticationCredentialResolver>());
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
    public void ProviderShouldNotResolveUsers()
    {
        var provider = CreateProvider();

        Assert.That(provider, Is.Not.InstanceOf<IAuthenticationUserResolver>());
    }

    [Test]
    public async Task ProviderAuthenticateAsyncResilientToWhitespace()
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

        // Note the spaces around the code
        var result = await provider.AuthenticateAsync(new TotpAssertion($"  {code}  "), credential);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.SucceededWithCredentialUpdate));
    }

    [Test]
    public async Task OrchestratorIntegrationTest()
    {
        // This test proves that the orchestrator uses the pipeline (and thus our provider) for verification.
        var pipeline = new Mock<IAuthenticationPipeline>();
        var factorPipeline = new Mock<IAuthenticationFactorPipeline>();
        var handshakeService = new Mock<TestAuthenticationHandshakeOrchestrationService>();
        var handshakeCompletionService = new TestAuthenticationHandshakeCompletionService();
        var policyEvaluator = new Mock<IMfaPolicyEvaluator>();
        var providerRegistry = new Mock<IAuthenticationProviderRegistry>();
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.FactorType).Returns(AuthenticationFactorTypes.Totp);
        provider.Setup(item => item.CanSatisfyFactor(It.IsAny<string>()))
            .Returns<string>(factorType => AuthenticationFactorTypes.Matches(AuthenticationFactorTypes.Totp, factorType));
        IAuthenticationProvider? providerObject = provider.Object;
        providerRegistry.Setup(item => item.TryGetProvider(It.IsAny<IAuthenticationAssertion>(), out providerObject)).Returns(true);
        var orchestrator = new AuthenticationOrchestrator(pipeline.Object, factorPipeline.Object, handshakeService.Object, handshakeCompletionService, policyEvaluator.Object, providerRegistry.Object);

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

        var assertion = new TotpAssertion("123456");
        var context = new AuthenticationContext();

        var responseUser = new Mock<IUser>();
        responseUser.Setup(u => u.Id).Returns(userId);
        factorPipeline.Setup(x => x.VerifyFactorAsync(
                It.Is<AuthenticationContext>(c => c.UserId == userId),
                assertion,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, responseUser.Object, AuthenticationStatus.Success));

        handshakeService.Setup(x => x.BeginVerificationAsync(It.IsAny<BeginAuthenticationHandshakeVerificationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(handshake));
        handshakeCompletionService.CompletionResult = Result.Success(handshake);

        var result = await orchestrator.VerifyFactorAsync(handshakeToken, "totp", context, assertion);

        Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.HandshakeIncomplete));
        factorPipeline.Verify(x => x.VerifyFactorAsync(
            It.Is<AuthenticationContext>(c => c.UserId == userId),
            assertion,
            It.IsAny<CancellationToken>()), Times.Once);
    }
}
