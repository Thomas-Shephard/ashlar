using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

[TestFixture]
public class BootstrapServiceTests
{
    private Mock<IBootstrapStateRepository> _stateRepository;
    private Mock<IInvitationService> _invitationService;
    private Mock<IInvitationRepository> _invitationRepository;
    private Mock<IIdentityRepository> _identityRepository;
    private Mock<IAshlarTransactionProvider> _transactionProvider;
    private Mock<IAuthorizationGrantService> _grantService;
    private Mock<ISecureTokenGenerator> _tokenGenerator;
    private Mock<ISecureTokenHasher> _tokenHasher;
    private Mock<IUriValidator> _uriValidator;
    private FakeTimeProvider _timeProvider;
    private Mock<ISecurityEventSink> _securityEventSink;
    private BootstrapOptions _options;
    private InvitationDependencies _dependencies;
    private BootstrapService _service;

    [SetUp]
    public void SetUp()
    {
        _stateRepository = new Mock<IBootstrapStateRepository>();
        _invitationService = new Mock<IInvitationService>();
        _invitationRepository = new Mock<IInvitationRepository>();
        _identityRepository = new Mock<IIdentityRepository>();
        _transactionProvider = new Mock<IAshlarTransactionProvider>();
        _grantService = new Mock<IAuthorizationGrantService>();
        _tokenGenerator = new Mock<ISecureTokenGenerator>();
        _tokenHasher = new Mock<ISecureTokenHasher>();
        _uriValidator = new Mock<IUriValidator>();
        _timeProvider = new FakeTimeProvider();
        _securityEventSink = new Mock<ISecurityEventSink>();
        _options = new BootstrapOptions();

        var infrastructure = new IdentityInfrastructureContext(
            Mock.Of<Ashlar.Messaging.IEmailSender>(),
            Mock.Of<Ashlar.Identity.RateLimiting.Abstractions.IAuthenticationRateLimiter>(),
            _uriValidator.Object);
        var audit = new IdentityAuditContext(_timeProvider, _securityEventSink.Object);

        _dependencies = new InvitationDependencies(
            new InvitationStoreContext(_invitationRepository.Object, _identityRepository.Object, _transactionProvider.Object),
            new SecureTokenContext(_tokenGenerator.Object, _tokenHasher.Object),
            infrastructure,
            audit);

        _service = new BootstrapService(
            _stateRepository.Object,
            _invitationService.Object,
            _dependencies,
            _grantService.Object,
            Options.Create(_options));
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
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapService(
                null!,
                _invitationService.Object,
                _dependencies,
                _grantService.Object,
                Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapService(
                _stateRepository.Object,
                null!,
                _dependencies,
                _grantService.Object,
                Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapService(
                _stateRepository.Object,
                _invitationService.Object,
                null!,
                _grantService.Object,
                Options.Create(_options)));
            Assert.Throws<ArgumentNullException>(() => _ = new BootstrapService(
                _stateRepository.Object,
                _invitationService.Object,
                _dependencies,
                null!,
                Options.Create(_options)));
        }
    }

    [Test]
    public async Task ConstructorUsesDefaultOptionsWhenOptionsAreNull()
    {
        var service = new BootstrapService(
            _stateRepository.Object,
            _invitationService.Object,
            _dependencies,
            _grantService.Object);

        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);
        _tokenGenerator.Setup(g => g.GenerateToken()).Returns("raw-token");
        _tokenHasher.Setup(h => h.HashToken("raw-token")).Returns("hashed-token");

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var result = await service.CreateBootstrapInvitationAsync(new CreateBootstrapInvitationRequest { Email = "admin@example.com" });

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task CreateBootstrapInvitationAsyncFailsIfAlreadyInitialized()
    {
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Initialized);
        var result = await _service.CreateBootstrapInvitationAsync(new CreateBootstrapInvitationRequest { Email = "admin@example.com" });
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_initialized"));
        }
    }

    [Test]
    public async Task CreateBootstrapInvitationAsyncSucceedsAndReturnsToken()
    {
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);
        _tokenGenerator.Setup(g => g.GenerateToken()).Returns("raw-token");
        _tokenHasher.Setup(h => h.HashToken("raw-token")).Returns("hashed-token");

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var request = new CreateBootstrapInvitationRequest { Email = "admin@example.com", Metadata = "{\"existing\":\"data\"}" };
        var result = await _service.CreateBootstrapInvitationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo("raw-token"));
        }

        _invitationRepository.Verify(r => r.CreateInvitationAsync(It.Is<UserInvitation>(i =>
            i.Email == "admin@example.com" &&
            i.TokenHash == "hashed-token" &&
            i.Metadata != null &&
            i.Metadata.Contains("ashlar.bootstrap") &&
            i.Metadata.Contains("existing")), It.IsAny<CancellationToken>()), Times.Once);

        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void CreateBootstrapInvitationAsyncRejectsEmailWithLineBreaks()
    {
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);

        Assert.ThrowsAsync<ArgumentException>(() => _service.CreateBootstrapInvitationAsync(new CreateBootstrapInvitationRequest
        {
            Email = "admin@example.com\r\nBcc: attacker@example.com"
        }));

        _invitationRepository.Verify(r => r.CreateInvitationAsync(It.IsAny<UserInvitation>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task CreateBootstrapInvitationAsyncUsesRequestedExpiry()
    {
        _timeProvider.SetUtcNow(new DateTimeOffset(2026, 5, 9, 10, 0, 0, TimeSpan.Zero));
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);
        _tokenGenerator.Setup(g => g.GenerateToken()).Returns("raw-token");
        _tokenHasher.Setup(h => h.HashToken("raw-token")).Returns("hashed-token");

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var requestedExpiry = TimeSpan.FromHours(2);
        await _service.CreateBootstrapInvitationAsync(new CreateBootstrapInvitationRequest
        {
            Email = "admin@example.com",
            Expiry = requestedExpiry
        });

        _invitationRepository.Verify(r => r.CreateInvitationAsync(It.Is<UserInvitation>(i =>
            i.ExpiresAt == _timeProvider.GetUtcNow().Add(requestedExpiry)), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CreateBootstrapInvitationAsyncFailsWithInvalidExistingMetadata()
    {
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);
        _tokenGenerator.Setup(g => g.GenerateToken()).Returns("raw-token");
        _tokenHasher.Setup(h => h.HashToken("raw-token")).Returns("hashed-token");

        var request = new CreateBootstrapInvitationRequest { Email = "admin@example.com", Metadata = "invalid-json" };
        var result = await _service.CreateBootstrapInvitationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_metadata_format"));
        }
        _transactionProvider.Verify(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
        _invitationRepository.Verify(r => r.CreateInvitationAsync(It.IsAny<UserInvitation>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsWithInvalidMetadataJson()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "admin@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "not-json"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("not_a_bootstrap_invitation"));
        }
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsIfInvitationNotFound()
    {
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync((UserInvitation?)null);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_invitation"));
        }
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsIfNotBootstrapInvitation()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("not_a_bootstrap_invitation"));
        }
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsIfMetadataIsBlank()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = " "
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("not_a_bootstrap_invitation"));
        }
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsIfAlreadyInitialized()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{\"ashlar.bootstrap\": true}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Initialized);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_initialized"));
        }
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncSucceedsAndAssignsGrants()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "admin@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{\"ashlar.bootstrap\": true}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);

        var userId = Guid.NewGuid();
        _invitationService.Setup(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(userId));

        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
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
        _stateRepository.Setup(r => r.MarkAsInitializedAsync(userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(userId));
        }

        _grantService.Verify(s => s.CreateGrantAsync(It.Is<CreateAuthorizationGrantRequest>(r =>
            r.UserId == userId && r.Role == "admin"), It.IsAny<CancellationToken>()), Times.Once);

        _stateRepository.Verify(r => r.MarkAsInitializedAsync(userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once);
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsIfConcurrencyConflictOnMarkAsInitialized()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "admin@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{\"ashlar.bootstrap\": true}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);

        var userId = Guid.NewGuid();
        _invitationService.Setup(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(userId));

        _stateRepository.Setup(r => r.MarkAsInitializedAsync(userId, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("already_initialized"));
        }
        transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncFailsIfGrantCreationFails()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "admin@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{\"ashlar.bootstrap\": true}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);

        var userId = Guid.NewGuid();
        _invitationService.Setup(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(userId));
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AuthorizationGrant>("invalid_grant_shape"));

        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin", Permission = "manage" });

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("invalid_grant_shape"));
        }

        _stateRepository.Verify(r => r.MarkAsInitializedAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncUsesDefaultFailureWhenGrantCreationFailsWithoutReason()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "admin@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{\"ashlar.bootstrap\": true}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);

        var userId = Guid.NewGuid();
        _invitationService.Setup(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(userId));
        _grantService.Setup(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AuthorizationGrant>(false));

        _options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("grant_creation_failed"));
        }

        transaction.Verify(t => t.RollbackAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task AcceptBootstrapInvitationAsyncReturnsFailureIfInvitationAcceptanceFails()
    {
        var invitation = new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "admin@example.com",
            TokenHash = "hashed",
            CreatedAt = _timeProvider.GetUtcNow(),
            ExpiresAt = _timeProvider.GetUtcNow().AddDays(1),
            Version = "1",
            Metadata = "{\"ashlar.bootstrap\": true}"
        };
        _tokenHasher.Setup(h => h.HashToken("token")).Returns("hashed");
        _invitationRepository.Setup(r => r.GetInvitationByTokenHashAsync("hashed", It.IsAny<CancellationToken>())).ReturnsAsync(invitation);
        _stateRepository.Setup(r => r.GetBootstrapStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync(BootstrapStatus.Uninitialized);
        _invitationService.Setup(s => s.AcceptInvitationAsync(It.IsAny<AcceptInvitationRequest>(), It.IsAny<AuthenticationContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<Guid>("email_mismatch"));

        var transaction = new Mock<IAshlarTransaction>();
        _transactionProvider.Setup(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);

        var result = await _service.AcceptBootstrapInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Is.EqualTo("email_mismatch"));
        }

        _grantService.Verify(s => s.CreateGrantAsync(It.IsAny<CreateAuthorizationGrantRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        _stateRepository.Verify(r => r.MarkAsInitializedAsync(It.IsAny<Guid>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never);
        transaction.Verify(t => t.CommitAsync(It.IsAny<CancellationToken>()), Times.Never);
    }
}
