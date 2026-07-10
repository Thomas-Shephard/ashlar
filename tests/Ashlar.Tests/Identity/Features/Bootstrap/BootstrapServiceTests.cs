using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Bootstrap;

[TestFixture]
internal sealed class BootstrapServiceTests
{
    private const string SetupSecret = "operator-setup-secret";
    private const string SetupSecretHash = "sha256:setup-secret-hash";
    private const string WrongSetupSecret = "wrong-setup-secret";

    private Mock<IBootstrapStateRepository> _stateRepository = null!;
    private Mock<IUserRepository> _userRepository = null!;
    private Mock<IAshlarTransactionProvider> _transactionProvider = null!;
    private Mock<IAuthorizationGrantService> _grantService = null!;
    private Mock<IAuthenticationRateLimiter> _rateLimiter = null!;
    private Mock<ISecureTokenGenerator> _tokenGenerator = null!;
    private Mock<ISecureTokenHasher> _tokenHasher = null!;
    private FakeTimeProvider _timeProvider = null!;
    private Mock<ISecurityEventSink> _securityEventSink = null!;
    private BootstrapOptions _options = null!;
    private SecureTokenContext _tokenContext = null!;
    private IdentityAuditContext _auditContext = null!;
    private BootstrapService _service = null!;

    [SetUp]
    public void SetUp()
    {
        _stateRepository = new Mock<IBootstrapStateRepository>();
        _userRepository = new Mock<IUserRepository>();
        _transactionProvider = new Mock<IAshlarTransactionProvider>();
        _grantService = new Mock<IAuthorizationGrantService>();
        _rateLimiter = new Mock<IAuthenticationRateLimiter>();
        _tokenGenerator = new Mock<ISecureTokenGenerator>();
        _tokenHasher = new Mock<ISecureTokenHasher>();
        _timeProvider = new FakeTimeProvider();
        _securityEventSink = new Mock<ISecurityEventSink>();
        _options = new BootstrapOptions { SetupSecret = SetupSecret };

        _tokenHasher.Setup(h => h.HashToken(SetupSecret)).Returns(SetupSecretHash);
        _tokenHasher.Setup(h => h.HashToken(WrongSetupSecret)).Returns("sha256:wrong");
        _tokenHasher.Setup(h => h.HashToken(string.Empty)).Throws(new ArgumentException("Token is required.", "token"));
        _rateLimiter
            .Setup(l => l.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());

        _tokenContext = new SecureTokenContext(_tokenGenerator.Object, _tokenHasher.Object);
        _auditContext = new IdentityAuditContext(_timeProvider, _securityEventSink.Object);

        _service = CreateService();
    }

    [Test]
    public async Task GetStatusAsyncReturnsStatusFromRepository()
    {
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Initialized);

        var status = await _service.GetStatusAsync();

        Assert.That(status, Is.EqualTo(BootstrapStatus.Initialized));
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorThrowsOnNullArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapService(null!, Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapStoreContext(
                null!,
                _userRepository.Object,
                _transactionProvider.Object));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapStoreContext(
                _stateRepository.Object,
                null!,
                _transactionProvider.Object));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapStoreContext(
                _stateRepository.Object,
                _userRepository.Object,
                null!));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapDependencies(
                null!,
                _tokenContext,
                CreateInfrastructureContext(),
                _auditContext));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapDependencies(
                CreateStoreContext(),
                null!,
                CreateInfrastructureContext(),
                _auditContext));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapDependencies(
                CreateStoreContext(),
                _tokenContext,
                null!,
                _auditContext));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapDependencies(
                CreateStoreContext(),
                _tokenContext,
                CreateInfrastructureContext(),
                null!));
        }
    }

    [Test]
    public void ConstructorThrowsWhenBootstrapGrantsRequireGrantService()
    {
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });

        var exception = Assert.Throws<InvalidOperationException>(() => _ = CreateService(includeGrantService: false));

        Assert.That(exception?.Message, Does.Contain("built-in authorization"));
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsClosedWithDefaultOptions()
    {
        var service = new BootstrapService(CreateDependencies());
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        var result = await service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest { Email = "admin@example.com" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsIfAlreadyInitializedBeforeCreatingUser()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Initialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest { Email = "admin@example.com", SetupSecret = SetupSecret });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyInitialized));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == AshlarFailureCodes.AlreadyInitialized.Value), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncDoesNotStoreAlreadyInitializedEmailInAuditWhenDisabled()
    {
        _options.StoreEmailInAudit = false;
        ArrangeBootstrapStatus(BootstrapStatus.Initialized);

        await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.Properties != null &&
            !e.Properties.ContainsKey("email")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncStoresAlreadyInitializedEmailInAuditByDefault()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Initialized);

        await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "Admin@Example.com",
            SetupSecret = SetupSecret
        });

        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.Properties != null &&
            e.Properties.ContainsKey("email") &&
            e.Properties["email"] == "Admin@Example.com"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsWithMissingSetupAuthorizationWithoutMutatingUsers()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com"
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == SecurityEventFailureReasons.BootstrapSetupAuthorizationInvalid), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsWhenConfiguredSetupSecretIsBlankEvenIfSuppliedSecretIsBlank()
    {
        _options.SetupSecret = string.Empty;
        _tokenHasher.Setup(h => h.HashToken(string.Empty)).Returns("sha256:empty");
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = string.Empty
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _tokenHasher.Verify(h => h.HashToken(string.Empty), Times.Never);
        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == SecurityEventFailureReasons.BootstrapSetupAuthorizationMissing), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsWithWrongSetupAuthorizationWithoutMutatingUsers()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = WrongSetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == SecurityEventFailureReasons.BootstrapSetupAuthorizationInvalid), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsWithOverlongSuppliedSetupSecretWithoutMutatingUsers()
    {
        var overlongSecret = new string('a', 257);
        _tokenHasher.Setup(h => h.HashToken(overlongSecret)).Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = overlongSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == SecurityEventFailureReasons.BootstrapSetupAuthorizationInvalid), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsClosedWhenConfiguredSetupSecretIsOverlong()
    {
        var overlongSecret = new string('a', 257);
        _options.SetupSecret = overlongSecret;
        _tokenHasher.Setup(h => h.HashToken(overlongSecret)).Throws(new ArgumentException("Token exceeds maximum allowed length.", "token"));
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _tokenHasher.Verify(h => h.HashToken(SetupSecret), Times.Never);
        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == SecurityEventFailureReasons.BootstrapSetupAuthorizationMissing), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsBeforeSetupAuthorizationWhenRateLimited()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);
        _rateLimiter
            .Setup(l => l.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision
            {
                Status = RateLimitStatus.Blocked,
                Remaining = 0,
                WindowResetAt = _timeProvider.GetUtcNow().AddMinutes(15)
            });
        var service = CreateService(rateLimiter: _rateLimiter.Object);

        var result = await service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        }, new AuthenticationContext(IpAddress: "203.0.113.10"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
        }

        _tokenHasher.Verify(h => h.HashToken(SetupSecret), Times.Never);
        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapRequested &&
            e.FailureReason == AshlarFailureCodes.RateLimited.Value), It.IsAny<CancellationToken>()), Times.Once);
        _rateLimiter.Verify(l => l.CheckAsync(It.Is<RateLimitAttempt>(a =>
            a.Purpose == "bootstrap-first-admin" &&
            a.IpAddress == "203.0.113.10" &&
            !string.IsNullOrWhiteSpace(a.Key)), It.Is<RateLimitRule>(r => r.PermitLimit == 5), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncChecksSetupAuthorizationWhenRateLimitAllowsAttempt()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);
        _rateLimiter
            .Setup(l => l.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());
        var service = CreateService(rateLimiter: _rateLimiter.Object);

        var result = await service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = WrongSetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
        }

        _rateLimiter.Verify(l => l.CheckAsync(It.IsAny<RateLimitAttempt>(), It.IsAny<RateLimitRule>(), It.IsAny<CancellationToken>()), Times.Once);
        _tokenHasher.Verify(h => h.HashToken(WrongSetupSecret), Times.Once);
    }

    [Test]
    public void BootstrapFirstAdminAsyncRejectsEmailWithLineBreaks()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);

        Assert.ThrowsAsync<ArgumentException>(() => _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com\r\nBcc: attacker@example.com",
            SetupSecret = SetupSecret
        }));

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void BootstrapFirstAdminAsyncRejectsEmailWithLineBreaksBeforeInitializedAudit()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Initialized);

        Assert.ThrowsAsync<ArgumentException>(() => _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com\r\nBcc: attacker@example.com",
            SetupSecret = SetupSecret
        }));

        _securityEventSink.Verify(s => s.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncCreatesUserAssignsGrantsAndMarksInitialized()
    {
        var tenantId = Guid.NewGuid();
        var transaction = ArrangeSuccessfulBootstrap();
        _options.Grants.Add(new BootstrapGrantTemplate { TenantId = tenantId, Role = "admin" });
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((CreateAuthorizationGrantRequest request, CancellationToken _) => Result.Success(new AuthorizationGrant
            {
                Id = Guid.NewGuid(),
                UserId = request.UserId,
                TenantId = request.TenantId,
                ScopeType = request.ScopeType,
                ScopeId = request.ScopeId,
                Role = request.Role,
                Permission = request.Permission,
                CreatedAt = _timeProvider.GetUtcNow()
            }));
        var context = new AuthenticationContext(
            UserId: Guid.NewGuid(),
            IpAddress: "203.0.113.10",
            UserAgent: "bootstrap-agent",
            CorrelationId: "bootstrap-correlation");

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "Admin@Example.com",
            UserName = "Admin",
            TenantId = tenantId,
            SetupSecret = SetupSecret
        }, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.Not.EqualTo(Guid.Empty));
        }

        _userRepository.Verify(r => r.GetUserByEmailAsync("Admin@Example.com", tenantId, It.IsAny<CancellationToken>()), Times.Once);
        _userRepository.Verify(r => r.CreateUserAsync(It.Is<IUser>(u =>
            u.Id == result.Value!.UserId &&
            u.DisplayEmail == "Admin@Example.com" &&
            u.Name == "Admin" &&
            u.CanSignIn() &&
            HasTenant(u, tenantId) &&
            u.EmailVerifiedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
        _grantService.Verify(s => s.CreateGrantAsync(It.Is<CreateAuthorizationGrantRequest>(r =>
            r.UserId == result.Value!.UserId &&
            r.TenantId == tenantId &&
            r.Role == "admin" &&
            r.Audit != null &&
            r.Audit.ActorUserId == context.UserId &&
            r.Audit.IpAddress == context.IpAddress &&
            r.Audit.UserAgent == context.UserAgent &&
            r.Audit.CorrelationId == context.CorrelationId &&
            r.Audit.Items != null &&
            HasAuditItem(r.Audit.Items, "system", "bootstrap")), It.IsAny<CancellationToken>()), Times.Once);
        _stateRepository.Verify(r => r.MarkAsInitializedAsync(result.Value!.UserId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once);
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncUsesSystemAuditForGrantCreationWithoutContext()
    {
        ArrangeSuccessfulBootstrap();
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((CreateAuthorizationGrantRequest request, CancellationToken _) => Result.Success(new AuthorizationGrant
            {
                Id = Guid.NewGuid(),
                UserId = request.UserId,
                Role = request.Role,
                CreatedAt = _timeProvider.GetUtcNow()
            }));

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        Assert.That(result.Succeeded, Is.True);
        _grantService.Verify(s => s.CreateGrantAsync(It.Is<CreateAuthorizationGrantRequest>(r =>
            r.Audit != null &&
            r.Audit.ActorUserId == null &&
            r.Audit.IpAddress == null &&
            r.Audit.UserAgent == null &&
            r.Audit.CorrelationId == null &&
            r.Audit.Items != null &&
            HasAuditItem(r.Audit.Items, "system", "bootstrap")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncPreservesRequestAuditForGrantCreation()
    {
        ArrangeSuccessfulBootstrap();
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((CreateAuthorizationGrantRequest request, CancellationToken _) => Result.Success(new AuthorizationGrant
            {
                Id = Guid.NewGuid(),
                UserId = request.UserId,
                Role = request.Role,
                CreatedAt = _timeProvider.GetUtcNow()
            }));
        var audit = new AuditContext(
            ActorUserId: Guid.NewGuid(),
            IpAddress: "203.0.113.20",
            UserAgent: "request-audit",
            CorrelationId: "request-correlation",
            Items: new Dictionary<string, string>
            {
                ["source"] = "operator",
                ["system"] = "request"
            });
        var context = new AuthenticationContext(
            UserId: Guid.NewGuid(),
            IpAddress: "203.0.113.30",
            UserAgent: "context-audit",
            CorrelationId: "context-correlation");

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret,
            Audit = audit
        }, context);

        Assert.That(result.Succeeded, Is.True);
        _grantService.Verify(s => s.CreateGrantAsync(It.Is<CreateAuthorizationGrantRequest>(r =>
            r.Audit != null &&
            r.Audit.ActorUserId == audit.ActorUserId &&
            r.Audit.IpAddress == audit.IpAddress &&
            r.Audit.UserAgent == audit.UserAgent &&
            r.Audit.CorrelationId == audit.CorrelationId &&
            r.Audit.Items != null &&
            HasAuditItem(r.Audit.Items, "source", "operator") &&
            HasAuditItem(r.Audit.Items, "system", "bootstrap")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFallsBackToContextWhenRequestAuditOmitsFieldsForGrantCreation()
    {
        ArrangeSuccessfulBootstrap();
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((CreateAuthorizationGrantRequest request, CancellationToken _) => Result.Success(new AuthorizationGrant
            {
                Id = Guid.NewGuid(),
                UserId = request.UserId,
                Role = request.Role,
                CreatedAt = _timeProvider.GetUtcNow()
            }));
        var context = new AuthenticationContext(
            UserId: Guid.NewGuid(),
            IpAddress: "203.0.113.40",
            UserAgent: "context-fallback",
            CorrelationId: "context-fallback-correlation");

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret,
            Audit = new AuditContext()
        }, context);

        Assert.That(result.Succeeded, Is.True);
        _grantService.Verify(s => s.CreateGrantAsync(It.Is<CreateAuthorizationGrantRequest>(r =>
            r.Audit != null &&
            r.Audit.ActorUserId == context.UserId &&
            r.Audit.IpAddress == context.IpAddress &&
            r.Audit.UserAgent == context.UserAgent &&
            r.Audit.CorrelationId == context.CorrelationId &&
            r.Audit.Items != null &&
            HasAuditItem(r.Audit.Items, "system", "bootstrap")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncCreatesUserWithoutGrantServiceWhenNoGrantsAreConfigured()
    {
        var transaction = ArrangeSuccessfulBootstrap();
        var service = CreateService(includeGrantService: false);

        var result = await service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.Not.EqualTo(Guid.Empty));
        }

        _grantService.Verify(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsBeforeCreatingUserWhenGrantsAreAddedAfterConstructionWithoutGrantService()
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);
        var service = CreateService(includeGrantService: false);
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });

        var result = await service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidConfiguration));
        }

        _transactionProvider.Verify(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapCompleted &&
            e.FailureReason == AshlarFailureCodes.InvalidConfiguration.Value), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncActivatesExistingDisabledUser()
    {
        var userId = Guid.NewGuid();
        ArrangeSuccessfulBootstrap(userId, existingUser: new AshlarUser
        {
            Id = userId,
            DisplayEmail = "admin@example.com",
            Name = "Old Name",
            AccountState = UserAccountState.Disabled
        });

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            UserName = "Admin",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(userId));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _userRepository.Verify(r => r.UpdateUserAsync(It.Is<IUser>(u =>
            u.Id == userId &&
            u.Name == "Admin" &&
            u.CanSignIn() &&
            u.EmailVerifiedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncVerifiesExistingActiveUnverifiedUser()
    {
        var userId = Guid.NewGuid();
        ArrangeSuccessfulBootstrap(userId, existingUser: new AshlarUser
        {
            Id = userId,
            DisplayEmail = "admin@example.com",
            Name = "Existing Admin",
            AccountState = UserAccountState.Active
        });

        await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        _userRepository.Verify(r => r.UpdateUserAsync(It.Is<IUser>(u =>
            u.Id == userId &&
            u.Name == "Existing Admin" &&
            u.CanSignIn() &&
            u.EmailVerifiedAt == _timeProvider.GetUtcNow()), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncUsesExistingActiveVerifiedUserWithoutUpdating()
    {
        var userId = Guid.NewGuid();
        ArrangeSuccessfulBootstrap(userId, existingUser: new AshlarUser
        {
            Id = userId,
            DisplayEmail = "admin@example.com",
            Name = "Existing Admin",
            AccountState = UserAccountState.Active,
            EmailVerifiedAt = _timeProvider.GetUtcNow().AddDays(-1)
        }, executeCommitCallbacks: true);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            UserName = "Ignored",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.EqualTo(userId));
        }

        _userRepository.Verify(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _userRepository.Verify(r => r.UpdateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.UserCreated), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncDoesNotStoreSetupSecretInAuditProperties()
    {
        ArrangeSuccessfulBootstrap(executeCommitCallbacks: true);

        await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        var auditText = string.Join("|", _securityEventSink.Invocations
            .Select(invocation => invocation.Arguments[0])
            .OfType<AshlarSecurityEvent>()
            .SelectMany(e => (e.Properties?.Values ?? []).Concat([e.FailureReason ?? string.Empty])));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(auditText, Does.Not.Contain(SetupSecret));
            Assert.That(auditText, Does.Not.Contain(SetupSecretHash));
        }
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsIfInitializedAfterSetupAuthorization()
    {
        var requestTenantId = Guid.NewGuid();
        var contextTenantId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        _stateRepository
            .SetupSequence(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(BootstrapStatus.Uninitialized)
            .ReturnsAsync(BootstrapStatus.Initialized);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            TenantId = requestTenantId,
            Audit = new AuditContext(ActorUserId: actorUserId, IpAddress: "203.0.113.1", UserAgent: "audit-agent", CorrelationId: "audit-correlation"),
            SetupSecret = SetupSecret
        }, new AuthenticationContext(TenantId: contextTenantId, UserId: Guid.NewGuid(), IpAddress: "198.51.100.2", UserAgent: "context-agent", CorrelationId: "context-correlation"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyInitialized));
        }

        _userRepository.Verify(s => s.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>()), Times.Never);
        _securityEventSink.Verify(s => s.RecordAsync(It.Is<AshlarSecurityEvent>(e =>
            e.EventType == AshlarSecurityEventTypes.BootstrapCompleted &&
            e.FailureReason == AshlarFailureCodes.AlreadyInitialized.Value &&
            e.TenantId == requestTenantId &&
            e.ActorUserId == actorUserId &&
            e.IpAddress == "203.0.113.1" &&
            e.UserAgent == "audit-agent" &&
            e.CorrelationId == "audit-correlation"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncAwaitsInitializedFailureAudit()
    {
        _stateRepository
            .SetupSequence(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(BootstrapStatus.Uninitialized)
            .ReturnsAsync(BootstrapStatus.Initialized);
        _securityEventSink
            .Setup(s => s.RecordAsync(It.IsAny<AshlarSecurityEvent>(), It.IsAny<CancellationToken>()))
            .Returns(async () => await Task.Yield());

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyInitialized));
        }
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsIfGrantCreationFails()
    {
        var transaction = ArrangeSuccessfulBootstrap();
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin", Permission = "manage" });
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthorizationGrant>(AshlarFailureCodes.InvalidGrantShape));

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidGrantShape));
        }

        _stateRepository.Verify(r => r.MarkAsInitializedAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncUsesDefaultFailureWhenGrantCreationFailsWithoutReason()
    {
        ArrangeSuccessfulBootstrap();
        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AuthorizationGrant>(false));

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.GrantCreationFailed));
        }
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncFailsIfConcurrencyConflictOnMarkAsInitialized()
    {
        var transaction = ArrangeSuccessfulBootstrap(markInitialized: false);

        var result = await _service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyInitialized));
        }

        transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task BootstrapFirstAdminAsyncSendsNotificationWhenCommittedUserCanBeLoaded()
    {
        var userId = Guid.NewGuid();
        ArrangeSuccessfulBootstrap(executeCommitCallbacks: true);
        _userRepository.Setup(r => r.GetUserByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid id, CancellationToken _) => new AshlarUser { Id = id, DisplayEmail = "admin@example.com", AccountState = UserAccountState.Active });
        var notificationService = new Mock<ISecurityNotificationService>();
        notificationService.Setup(s => s.NotifyAsync(It.IsAny<SecurityNotification>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityNotificationResult.Success());
        var service = CreateService(notificationService.Object);

        var result = await service.BootstrapFirstAdminAsync(new BootstrapFirstAdminRequest
        {
            Email = "admin@example.com",
            SetupSecret = SetupSecret
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value!.UserId, Is.Not.EqualTo(Guid.Empty));
        }

        notificationService.Verify(s => s.NotifyAsync(It.Is<SecurityNotification>(n =>
            n.Type == SecurityNotificationType.BootstrapCompleted &&
            n.RecipientEmail == "admin@example.com"), It.IsAny<CancellationToken>()), Times.Once);
    }

    private BootstrapService CreateService(ISecurityNotificationService? notificationService = null, bool includeGrantService = true, IAuthenticationRateLimiter? rateLimiter = null)
    {
        return new BootstrapService(
            CreateDependencies(notificationService, includeGrantService, rateLimiter),
            Options.Create(_options));
    }

    private BootstrapDependencies CreateDependencies(ISecurityNotificationService? notificationService = null, bool includeGrantService = true, IAuthenticationRateLimiter? rateLimiter = null)
    {
        return new BootstrapDependencies(
            CreateStoreContext(),
            _tokenContext,
            CreateInfrastructureContext(rateLimiter),
            new IdentityAuditContext(_timeProvider, _securityEventSink.Object, notificationService),
            includeGrantService ? new BootstrapGrantService(_grantService.Object) : null);
    }

    private sealed class BootstrapGrantService(IAuthorizationGrantService inner) : IAuthorizationGrantBootstrapService
    {
        public Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default) =>
            inner.CreateGrantAsync(request, cancellationToken);
    }

    private BootstrapStoreContext CreateStoreContext()
    {
        return new BootstrapStoreContext(_stateRepository.Object, _userRepository.Object, _transactionProvider.Object);
    }

    private IdentityInfrastructureContext CreateInfrastructureContext(IAuthenticationRateLimiter? rateLimiter = null)
    {
        return new IdentityInfrastructureContext(
            Mock.Of<IEmailSender>(),
            rateLimiter ?? _rateLimiter.Object,
            Mock.Of<IUriValidator>());
    }

    private void ArrangeBootstrapStatus(BootstrapStatus status)
    {
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(status);
    }

    private Mock<IAshlarTransaction> ArrangeTransaction(bool executeCommitCallbacks = false)
    {
        var transaction = new Mock<IAshlarTransaction>();
        if (executeCommitCallbacks)
        {
            transaction
                .Setup(t => t.OnCommitted(It.IsAny<Func<CancellationToken, Task>>()))
                .Callback<Func<CancellationToken, Task>>(action => action(CancellationToken.None).GetAwaiter().GetResult());
        }

        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);
        return transaction;
    }

    private Mock<IAshlarTransaction> ArrangeSuccessfulBootstrap(
        Guid? userId = null,
        bool markInitialized = true,
        bool executeCommitCallbacks = false,
        AshlarUser? existingUser = null)
    {
        ArrangeBootstrapStatus(BootstrapStatus.Uninitialized);
        var transaction = ArrangeTransaction(executeCommitCallbacks);
        _userRepository
            .Setup(r => r.GetUserByEmailAsync(It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingUser);
        _userRepository.Setup(r => r.CreateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        _userRepository.Setup(r => r.UpdateUserAsync(It.IsAny<IUser>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        if (existingUser != null)
        {
            _stateRepository.Setup(r => r.MarkAsInitializedAsync(userId ?? existingUser.Id, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(markInitialized);
        }
        else
        {
            _stateRepository.Setup(r => r.MarkAsInitializedAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(markInitialized);
        }

        return transaction;
    }

    private static bool HasTenant(IUser user, Guid? tenantId)
    {
        return user is ITenantUser tenantUser && tenantUser.TenantId == tenantId;
    }

    private static bool HasAuditItem(IReadOnlyDictionary<string, string> items, string key, string value)
    {
        return items.TryGetValue(key, out var actual) && actual == value;
    }
}
