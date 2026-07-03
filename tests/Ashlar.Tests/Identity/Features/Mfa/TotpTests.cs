using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
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
    private Mock<ICredentialService> _credentialService = null!;
    private Mock<IAshlarTransactionProvider> _transactionProvider = null!;
    private Mock<IAshlarTransaction> _transaction = null!;
    private Mock<ISecurityEventSink> _securityEvents = null!;
    private FakeTimeProvider _timeProvider = null!;
    private TotpOptions _options = null!;

    [SetUp]
    public void SetUp()
    {
        _repository = new Mock<IUserRepository>();
        _credentialRepository = new Mock<ICredentialRepository>();
        _credentialService = new Mock<ICredentialService>();
        _transactionProvider = new Mock<IAshlarTransactionProvider>();
        _transaction = new Mock<IAshlarTransaction>();
        var onCommitted = new List<Func<CancellationToken, Task>>();
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
        _credentialService.Setup(x => x.LinkCredentialAsync(
                It.IsAny<Guid>(),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<IAuthenticationProvider>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success());
        _credentialRepository.Setup(x => x.ListCredentialsForUserAsync(It.IsAny<Guid>(), true, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<UserCredential>());
        _repository.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid userId, CancellationToken _) => new User { Id = userId, DisplayEmail = "user@example.com" });
    }

    private TotpService CreateService()
    {
        return new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider()],
            new TotpServiceDependencies(Options.Create(_options), _timeProvider, _securityEvents.Object));
    }

    private static Task<TotpEnrollment> StartEnrollmentAsync(
        TotpService service,
        Guid userId,
        string issuer,
        string accountName,
        TenantContext? tenant = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default)
    {
        return service.StartEnrollmentPrivilegedAsync(
            new StartTotpEnrollmentRequest(userId, issuer, accountName)
            {
                Tenant = tenant,
                Audit = audit ?? new AuditContext()
            },
            cancellationToken);
    }

    private static Task<Result> CompleteEnrollmentAsync(
        TotpService service,
        Guid userId,
        string sharedSecret,
        string code,
        TenantContext? tenant = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default)
    {
        return service.CompleteEnrollmentPrivilegedAsync(
            new VerifyTotpEnrollmentRequest(userId, sharedSecret, code)
            {
                Tenant = tenant,
                Audit = audit ?? new AuditContext()
            },
            cancellationToken);
    }

    private static Task<bool> DisableAsync(
        TotpService service,
        Guid userId,
        TenantContext? tenant = null,
        AuditContext? audit = null,
        CancellationToken cancellationToken = default)
    {
        return service.DisablePrivilegedAsync(
            new DisableTotpRequest(userId)
            {
                Tenant = tenant,
                Audit = audit ?? new AuditContext()
            },
            cancellationToken);
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
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider(), CreateSecondaryProvider(recoveryProvider)],
            new TotpServiceDependencies(Options.Create(_options), _timeProvider, _securityEvents.Object));
    }

    private static ISecondaryAuthenticationFactorProvider CreateSecondaryProvider(AuthenticationProviderKey providerKey)
    {
        var provider = new Mock<ISecondaryAuthenticationFactorProvider>();
        provider.SetupGet(item => item.Key).Returns(providerKey);
        provider.SetupGet(item => item.FactorType).Returns(providerKey.Name);
        return provider.Object;
    }

    private static FreshMfaVerificationProof CreateProof(Guid userId, TenantContext? tenant = null, DateTimeOffset? expiresAt = null)
    {
        var verifiedAt = DateTimeOffset.UtcNow;
        return new FreshMfaVerificationProof(userId, tenant?.TenantId, Guid.NewGuid(), verifiedAt, expiresAt ?? verifiedAt.AddMinutes(10));
    }

    private static FreshPrimaryAuthenticationProof CreatePrimaryProof(Guid userId, TenantContext? tenant = null, DateTimeOffset? expiresAt = null)
    {
        var authenticatedAt = DateTimeOffset.UtcNow;
        return new FreshPrimaryAuthenticationProof(userId, tenant?.TenantId, Guid.NewGuid(), authenticatedAt, expiresAt ?? authenticatedAt.AddMinutes(10));
    }

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
        var deps = new TotpServiceDependencies(Options.Create(_options));

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(null!, _credentialRepository.Object, _credentialService.Object, _transactionProvider.Object, [provider], deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, null!, _credentialService.Object, _transactionProvider.Object, [provider], deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, null!, _transactionProvider.Object, [provider], deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService.Object, null!, [provider], deps));
            Assert.Throws<ArgumentNullException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService.Object, _transactionProvider.Object, [provider], null!));
            Assert.Throws<InvalidOperationException>(() => _ = new TotpService(_repository.Object, _credentialRepository.Object, _credentialService.Object, _transactionProvider.Object, [], deps));
        }
    }

    [Test]
    public void TotpServiceConstructorAllowsDefaultTimeProvider()
    {
        Assert.DoesNotThrow(() => _ = new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider()],
            new TotpServiceDependencies(Options.Create(_options))));
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

        var enrollment = await StartEnrollmentAsync(service, userId, "Ashlar", "user@example.com");

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
            _repository.Verify(x => x.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
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

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongUser?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(wrongTenant?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
        }
    }

    [Test]
    public async Task StartEnrollmentAsyncShouldRejectTenantMismatchBeforeReturningSecret()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var userTenantId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        _repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = userTenantId });

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() =>
            StartEnrollmentAsync(service, userId, "Ashlar", "user@example.com", new TenantContext(requestedTenantId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception?.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
                d.EventType == AshlarSecurityEventTypes.TotpEnrollmentStarted &&
                d.Outcome == SecurityEventOutcomes.Failure &&
                d.UserId == userId &&
                d.TenantId == requestedTenantId &&
                d.FailureReason == AshlarFailureCodes.TenantMismatch.Value &&
                d.Properties == null), It.IsAny<CancellationToken>()), Times.Once);
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
    public void StartEnrollmentAsyncWithEmptyUserIdShouldThrow()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() => StartEnrollmentAsync(service, Guid.Empty, "Ashlar", "user@example.com"));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public void StartEnrollmentAsyncWithInvalidIssuerShouldThrow(string? issuer)
    {
        var service = CreateService();

        Assert.That(
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.CatchAsync(() => StartEnrollmentAsync(service, Guid.NewGuid(), issuer!, "user@example.com")),
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
            Assert.CatchAsync(() => StartEnrollmentAsync(service, Guid.NewGuid(), "Ashlar", accountName!)),
            Is.TypeOf<ArgumentException>().Or.TypeOf<ArgumentNullException>());
    }

    [Test]
    public async Task CompleteEnrollmentAsyncSucceedsWithCorrectCode()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        var result = await CompleteEnrollmentAsync(service, userId, secret, code);

        Assert.That(result.Succeeded, Is.True);
        _credentialService.Verify(x => x.LinkCredentialAsync(userId, It.IsAny<TotpAssertion>(), It.IsAny<IAuthenticationProvider>(), secret, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()), Times.Once);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpEnrollmentCompleted), It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldAcceptMatchingFreshMfaProof()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);
        var proof = CreateProof(userId);
        SetupExistingTotp(userId);

        var result = await service.CompleteEnrollmentAsync(new VerifyTotpEnrollmentRequest(userId, secret, code)
        {
            FreshMfaProof = proof,
            CurrentSessionId = proof.SessionId
        });

        Assert.That(result.Succeeded, Is.True);
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
    public async Task CompleteEnrollmentAsyncPropagatesAuditToEventAndNotification()
    {
        var userId = Guid.NewGuid();
        var audit = new AuditContext(ActorUserId: userId, IpAddress: "203.0.113.40", UserAgent: "totp-agent", CorrelationId: "totp-correlation");
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider()],
            new TotpServiceDependencies(Options.Create(_options), _timeProvider, _securityEvents.Object, notificationService.Object));
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);
        var tenantId = Guid.NewGuid();

        _repository.Setup(x => x.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com", TenantId = tenantId });

        var result = await CompleteEnrollmentAsync(service, userId, secret, code, new TenantContext(tenantId), audit);

        Assert.That(result.Succeeded, Is.True);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpEnrollmentCompleted &&
            d.TenantId == tenantId &&
            d.ActorUserId == userId &&
            d.IpAddress == "203.0.113.40" &&
            d.UserAgent == "totp-agent" &&
            d.CorrelationId == "totp-correlation"), It.IsAny<CancellationToken>()), Times.Once);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.TotpEnrolled &&
            notification.IpAddress == "203.0.113.40" &&
            notification.UserAgent == "totp-agent"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncUsesReplaceCredentialPath()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        var result = await CompleteEnrollmentAsync(service, userId, secret, code);

        Assert.That(result.Succeeded, Is.True);
        _credentialService.Verify(x => x.LinkCredentialAsync(userId, It.IsAny<TotpAssertion>(), It.IsAny<IAuthenticationProvider>(), secret, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncShouldRejectTenantMismatchBeforeReplacingCredential()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = Guid.NewGuid() });

        var result = await CompleteEnrollmentAsync(service, userId, secret, code, new TenantContext(requestedTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _credentialService.Verify(x => x.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
                d.EventType == AshlarSecurityEventTypes.TotpEnrollmentCompleted &&
                d.Outcome == SecurityEventOutcomes.Failure &&
                d.TenantId == requestedTenantId &&
                d.FailureReason == AshlarFailureCodes.TenantMismatch.Value &&
                d.Properties == null), It.IsAny<CancellationToken>()), Times.Once);
        }
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
            _credentialService.Verify(x => x.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _securityEvents.Verify(x => x.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncReplacesExistingCredential()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);

        var result = await CompleteEnrollmentAsync(service, userId, secret, code);

        Assert.That(result.Succeeded, Is.True);
        _credentialRepository.Verify(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncFailsWithIncorrectCode()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);

        var result = await CompleteEnrollmentAsync(service, userId, secret, "000000");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCode));
        }
        _credentialService.Verify(x => x.LinkCredentialAsync(It.IsAny<Guid>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<IAuthenticationProvider>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase("link_failed")]
    [TestCase(null)]
    public async Task CompleteEnrollmentAsyncFailsWhenCredentialLinkFails(string? failureReason)
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var secretBytes = new byte[20];
        System.Security.Cryptography.RandomNumberGenerator.Fill(secretBytes);
        var secret = Base32.Encode(secretBytes);
        var code = TotpAuthenticator.GenerateCode(secretBytes, _timeProvider.GetUtcNow().ToUnixTimeSeconds() / 30);

        _credentialService.Setup(x => x.LinkCredentialAsync(
                userId,
                It.IsAny<TotpAssertion>(),
                It.IsAny<IAuthenticationProvider>(),
                secret,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result(false, failureReason is null ? null : new AshlarFailure(new AshlarFailureCode(failureReason))));

        var result = await CompleteEnrollmentAsync(service, userId, secret, code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo(failureReason ?? "link_failed"));
        }

        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpEnrollmentCompleted &&
            d.Outcome == SecurityEventOutcomes.Failure &&
            d.FailureReason == (failureReason ?? "link_failed")), It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CompleteEnrollmentAsyncFailsWithEmptyCode()
    {
        var service = CreateService();
        var result = await CompleteEnrollmentAsync(service, Guid.NewGuid(), "secret", "");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.EmptyCode));
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncFailsWithInvalidSecret()
    {
        var service = CreateService();
        var result = await CompleteEnrollmentAsync(service, Guid.NewGuid(), "invalid-base32!", "123456");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecretFormat));
        }
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    public async Task CompleteEnrollmentAsyncFailsWithMissingSharedSecret(string? sharedSecret)
    {
        var service = CreateService();

        // ReSharper disable once NullableWarningSuppressionIsUsed
        var result = await CompleteEnrollmentAsync(service, Guid.NewGuid(), sharedSecret!, "123456");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }
    }

    [Test]
    public async Task CompleteEnrollmentAsyncFailsWithTooLongSharedSecret()
    {
        var service = CreateService();
        var sharedSecret = new string('A', 257);

        var result = await CompleteEnrollmentAsync(service, Guid.NewGuid(), sharedSecret, "123456");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }
    }

    [Test]
    public void CompleteEnrollmentAsyncWithEmptyUserIdShouldThrow()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() => CompleteEnrollmentAsync(service, Guid.Empty, "secret", "123456"));
    }

    [Test]
    public async Task DisableAsyncSucceedsWhenCredentialExists()
    {
        var notificationService = new Mock<ISecurityNotificationService>();
        var service = new TotpService(
            _repository.Object,
            _credentialRepository.Object,
            _credentialService.Object,
            _transactionProvider.Object,
            [CreateProvider()],
            new TotpServiceDependencies(Options.Create(_options), _timeProvider, _securityEvents.Object, notificationService.Object));
        var userId = Guid.NewGuid();

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);
        _repository.Setup(x => x.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "user@example.com" });

        var result = await DisableAsync(service, userId);

        Assert.That(result, Is.True);
        _credentialRepository.Verify(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()), Times.Once);
        _transaction.Verify(x => x.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()), Times.Once);
        _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
            d.EventType == AshlarSecurityEventTypes.TotpDisabled), It.IsAny<CancellationToken>()), Times.Once);
        notificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.TotpDisabled &&
            notification.IpAddress == null &&
            notification.UserAgent == null), It.IsAny<CancellationToken>()), Times.Once);
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
            Audit = new AuditContext()
        });

        Assert.That(result, Is.True);
    }

    [Test]
    public void PrivilegedTotpManagementShouldRequireAudit()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => service.StartEnrollmentPrivilegedAsync(new StartTotpEnrollmentRequest(userId, "Ashlar", "user@example.com")));
            Assert.ThrowsAsync<ArgumentException>(() => service.CompleteEnrollmentPrivilegedAsync(new VerifyTotpEnrollmentRequest(userId, "secret", "123456")));
            Assert.ThrowsAsync<ArgumentException>(() => service.DisablePrivilegedAsync(new DisableTotpRequest(userId)));
        }
    }

    [Test]
    public void PrivilegedTotpManagementShouldRejectNullRequests()
    {
        var service = CreateService();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.StartEnrollmentPrivilegedAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteEnrollmentPrivilegedAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.DisablePrivilegedAsync(null!));
        }
    }

    [Test]
    public async Task DisableAsyncFailsWhenNoCredentialExists()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();

        _credentialRepository.Setup(x => x.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, It.IsAny<CancellationToken>()))
            .ReturnsAsync(0);

        var result = await DisableAsync(service, userId);

        Assert.That(result, Is.False);
    }

    [Test]
    public async Task DisableAsyncShouldRejectTenantMismatchBeforeRevokingCredential()
    {
        var service = CreateService();
        var userId = Guid.NewGuid();
        var requestedTenantId = Guid.NewGuid();
        _repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new User { Id = userId, DisplayEmail = "tenant@example.com", TenantId = Guid.NewGuid() });

        var result = await DisableAsync(service, userId, new TenantContext(requestedTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.False);
            _credentialRepository.Verify(x => x.RevokeCredentialsAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            _securityEvents.Verify(x => x.RecordAsync(It.Is<AshlarSecurityEvent>(d =>
                d.EventType == AshlarSecurityEventTypes.TotpDisabled &&
                d.Outcome == SecurityEventOutcomes.Failure &&
                d.TenantId == requestedTenantId &&
                d.FailureReason == AshlarFailureCodes.TenantMismatch.Value &&
                d.Properties == null), It.IsAny<CancellationToken>()), Times.Once);
        }
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
    public void DisableAsyncWithEmptyUserIdShouldThrow()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentException>(() => DisableAsync(service, Guid.Empty));
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
    public async Task ProviderResolveCredentialAsyncReturnsNullOnWrongAssertion()
    {
        var provider = CreateProvider();

        var result = await provider.ResolveCredentialAsync(Guid.NewGuid(), new Mock<IAuthenticationAssertion>().Object, null, _credentialRepository.Object);
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task ProviderResolveCredentialAsyncReturnsCredential()
    {
        var provider = CreateProvider();
        var userId = Guid.NewGuid();
        var assertion = new TotpAssertion("123456");
        var credential = new UserCredential { Id = Guid.NewGuid(), UserId = userId, ProviderType = _options.ProviderKey.Type, ProviderName = _options.ProviderKey.Name, ProviderKey = userId.ToString("D"), Status = CredentialStatus.Active, CreatedAt = DateTimeOffset.UtcNow, Version = "1" };

        _credentialRepository.Setup(x => x.GetCredentialForUserAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, userId.ToString("D"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);

        var result = await provider.ResolveCredentialAsync(userId, assertion, null, _credentialRepository.Object);

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
    public async Task ProviderFindUserAsyncReturnsNullForUserIdBecauseCredentialServiceOwnsFallback()
    {
        var provider = CreateProvider();
        var userId = Guid.NewGuid();
        var user = new User { Id = userId, DisplayEmail = "test@example.com" };
        var context = new AuthenticationContext(UserId: userId);

        _repository.Setup(r => r.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var found = await provider.FindUserAsync(new TotpAssertion("123456"), context, _repository.Object);

        Assert.That(found, Is.Null);
        _repository.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsNullOnWrongAssertion()
    {
        var provider = CreateProvider();
        var context = new AuthenticationContext(UserId: Guid.NewGuid());

        var found = await provider.FindUserAsync(new Mock<IAuthenticationAssertion>().Object, context, _repository.Object);

        Assert.That(found, Is.Null);
        _repository.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task ProviderFindUserAsyncReturnsNullWithoutUserId()
    {
        var provider = CreateProvider();
        var context = new AuthenticationContext();

        var found = await provider.FindUserAsync(new TotpAssertion("123456"), context, _repository.Object);

        Assert.That(found, Is.Null);
        _repository.Verify(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
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
        var handshakeService = new Mock<IAuthenticationHandshakeService>();
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
