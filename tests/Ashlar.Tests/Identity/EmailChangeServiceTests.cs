using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class EmailChangeServiceTests
{
    private static AshlarUser CreateUser(string email = "old@example.com") => new() { Id = Guid.NewGuid(), Email = email, IsActive = true };

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorThrowsOnNullDependencies()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new EmailChangeService(null!));
    }

    [Test]
    public void ConstructorUsesDefaultOptionsWhenOptionsAreNull()
    {
        var identityContext = new IdentityContext(new InMemoryIdentityRepository(), Mock.Of<IIdentityService>(), new NullTransactionProvider());
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher());
        var infrastructure = new IdentityInfrastructureContext(Mock.Of<IEmailSender>(), Mock.Of<IAuthenticationRateLimiter>(), Mock.Of<IUriValidator>());
        var audit = new IdentityAuditContext(new FakeTimeProvider(), new RecordingSecurityEventSink());

        var dependencies = new EmailChangeDependencies(identityContext, tokenContext, infrastructure, Mock.Of<IAuthenticationSessionRepository>(), Mock.Of<ISecretProtector>(), audit);
        var service = new EmailChangeService(dependencies, options: null);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task RequestChangeFailsForInvalidCallbackUri()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        fixture.UriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(false);
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("https://evil.com") };

        var result = await fixture.Service.RequestChangeAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Contains.Substring("not allowed"));
        }
    }

    [Test]
    public async Task RequestChangeSendsEmailAndStoresCredential()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") };

        var result = await fixture.Service.RequestChangeAsync(request);

        Assert.That(result.Succeeded, Is.True, result.FailureReason);
        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.IdentityRepository.Credentials.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("new@example.com"));
            Assert.That(credential.UserId, Is.EqualTo(user.Id));
            Assert.That(fixture.SecretProtector.Unprotect(credential.CredentialValue!), Is.EqualTo("new@example.com"));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailChangeRequested), Is.True);
        }
    }

    [Test]
    public async Task RequestChangePropagatesAuditMetadataToSecurityEvent()
    {
        var actorUserId = Guid.NewGuid();
        var user = CreateUser();
        var fixture = CreateFixture(user);
        var audit = new AuditContext(actorUserId, "203.0.113.20", "NUnit", "corr-change");
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm"), Audit = audit };

        var result = await fixture.Service.RequestChangeAsync(request);
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailChangeRequested);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True, result.FailureReason);
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo(audit.IpAddress));
            Assert.That(securityEvent.UserAgent, Is.EqualTo(audit.UserAgent));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo(audit.CorrelationId));
        }
    }

    [Test]
    public void RequestChangeRejectsEmailWithLineBreaks()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = " new@example.com\r\nBcc: attacker@example.com ", CallbackBaseUri = new Uri("http://localhost/confirm") };

        Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestChangeAsync(request));
    }

    [Test]
    public async Task RequestChangeFailsIfNewEmailIsSameAsCurrent()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "old@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") };

        var result = await fixture.Service.RequestChangeAsync(request);

        Assert.That(result.Succeeded, Is.False, "Should have failed because email is the same");
    }

    [Test]
    public async Task RequestChangeSameEmailWorksForNonTenantUser()
    {
        var user = new MetadataUser { Id = Guid.NewGuid(), Email = "old@example.com", IsActive = true };
        var fixture = CreateFixture(user);
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "old@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") };

        var result = await fixture.Service.RequestChangeAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailChangeFailed).TenantId, Is.Null);
        }
    }

    [Test]
    public async Task RequestChangeFailsIfUserNotFound()
    {
        var fixture = CreateFixture();

        var result = await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = Guid.NewGuid(), NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrInactive));
        }
    }

    [Test]
    public async Task RequestChangeRateLimits()
    {
        var user = CreateUser();
        var fixture = CreateFixture(users: [user], requestAllowed: false);

        var result = await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailChangeRateLimited), Is.True);
        }
    }

    [Test]
    public async Task RequestChangeRateLimitWorksForNonTenantUser()
    {
        var user = new MetadataUser { Id = Guid.NewGuid(), Email = "old@example.com", IsActive = true };
        var fixture = CreateFixture(users: [user], requestAllowed: false);

        var result = await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailChangeRateLimited).TenantId, Is.Null);
        }
    }

    [Test]
    public async Task RequestChangeSuppressesIfNewEmailIsAlreadyInUse()
    {
        var tenantId = Guid.NewGuid();
        var actorUserId = Guid.NewGuid();
        var user = CreateUser() with { TenantId = tenantId };
        var existingUser = CreateUser("taken@example.com") with { TenantId = tenantId };
        var fixture = CreateFixture(users: [user, existingUser]);
        var audit = new AuditContext(actorUserId, "203.0.113.30", "NUnit", "corr-suppress");
        var request = new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "taken@example.com", CallbackBaseUri = new Uri("http://localhost/confirm"), Audit = audit };

        var result = await fixture.Service.RequestChangeAsync(request);
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailChangeRequestSuppressed);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.EmailSender.Messages, Has.Count.EqualTo(1));
            Assert.That(fixture.EmailSender.Messages.Single().TextBody, Contains.Substring("No changes were made"));
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo(audit.IpAddress));
        }
    }

    [Test]
    public async Task ConfirmChangeUpdatesUserAndRevokesSessions()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser() with { TenantId = tenantId };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.Audit.Events.Clear();

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });
        var updatedUser = await fixture.IdentityRepository.GetUserByIdAsync(user.Id);
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailChanged);

        Assert.That(updatedUser, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True, result.FailureReason);
            Assert.That(updatedUser.Email, Is.EqualTo("new@example.com"));
            Assert.That(updatedUser.EmailVerifiedAt, Is.Not.Null);
            Assert.That(fixture.SessionRepository.RevokedUserId, Is.EqualTo(user.Id));
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task ConfirmChangeRejectsStoredEmailWithLineBreaks()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var credential = fixture.IdentityRepository.Credentials.Single();
        credential.CredentialValue = fixture.SecretProtector.Protect(" changed@example.com\r\nBcc: attacker@example.com ");
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidTokenData));
        }
    }

    [Test]
    public async Task ConfirmChangeNotifiesOldAndNewEmailAddresses()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        Assert.That(result.Succeeded, Is.True, result.FailureReason);
        fixture.NotificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.EmailChanged &&
            notification.RecipientEmail == "old@example.com" &&
            notification.Metadata != null &&
            notification.Metadata["old_email"] == "old@example.com" &&
            notification.Metadata["new_email"] == "new@example.com"), It.IsAny<CancellationToken>()), Times.Once);
        fixture.NotificationService.Verify(n => n.NotifyAsync(It.Is<SecurityNotification>(notification =>
            notification.Type == SecurityNotificationType.EmailChanged &&
            notification.RecipientEmail == "new@example.com" &&
            notification.Metadata != null &&
            notification.Metadata["old_email"] == "old@example.com" &&
            notification.Metadata["new_email"] == "new@example.com"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ConfirmChangeFailsIfNewEmailBecameTaken()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser() with { TenantId = tenantId };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        // Now someone else takes the email
        var otherUser = CreateUser("new@example.com") with { TenantId = tenantId };
        fixture.IdentityRepository.Users.Add(otherUser);
        fixture.Audit.Events.Clear();

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.EmailAlreadyInUse));
            Assert.That(fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailChangeFailed).TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task ConfirmChangePreservesAuditMetadataForMetadataBackedUser()
    {
        var user = new MetadataUser { Id = Guid.NewGuid(), Email = "old@example.com", IsActive = true, CreatedAt = DateTimeOffset.UtcNow.AddDays(-1) };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True, result.FailureReason);
            Assert.That(user.Email, Is.EqualTo("new@example.com"));
            Assert.That(user.UpdatedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task ConfirmChangeRateLimits()
    {
        var user = CreateUser();
        var fixture = CreateFixture(users: [user], verifyAllowed: false);

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailChangeVerificationRateLimited), Is.True);
        }
    }

    [Test]
    public async Task ConfirmChangeFailsForInvalidToken()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = "invalid" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
        }
    }

    [Test]
    public async Task ConfirmChangeFailsForInvalidTokenData()
    {
        var user = CreateUser();
        var fixture = CreateFixture(users: [user], secretProtector: new ThrowingSecretProtector());
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidTokenData));
        }
    }

    [Test]
    public async Task ConfirmChangeFailsIfUserNoLongerExists()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.IdentityRepository.Users.Clear();

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrInactive));
        }
    }

    [Test]
    public async Task ConfirmChangeFailsIfCredentialWasConsumedConcurrently()
    {
        var user = CreateUser();
        var fixture = CreateFixture(users: [user], consumeSucceeds: false);
        await fixture.Service.RequestChangeAsync(new RequestEmailChangeRequest { UserId = user.Id, NewEmail = "new@example.com", CallbackBaseUri = new Uri("http://localhost/confirm") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmChangeAsync(new ConfirmEmailChangeRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TokenConsumptionFailed));
        }
    }

    private static string ExtractToken(EmailMessage message)
    {
        var body = message.TextBody!;
        var uri = new Uri(body.Split(": ").Last());
        return System.Web.HttpUtility.ParseQueryString(uri.Query)["t"]!;
    }

    private static Fixture CreateFixture(
        IUser? user = null,
        IUser?[]? users = null,
        bool requestAllowed = true,
        bool verifyAllowed = true,
        bool consumeSucceeds = true,
        ISecretProtector? secretProtector = null)
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 9, 12, 0, 0, TimeSpan.Zero));
        var identityRepository = new InMemoryIdentityRepository(users ?? [user]);
        var audit = new RecordingSecurityEventSink();
        var emailSender = new RecordingEmailSender();
        var tokenHasher = new Sha256TokenHasher();
        var tokenGenerator = new SecureTokenGenerator();
        var transactionProvider = new NullTransactionProvider();
        var rateLimiter = new StubRateLimiter(requestAllowed, verifyAllowed);
        var resolvedSecretProtector = secretProtector ?? new FakeSecretProtector();
        var sessionRepository = new StubSessionRepository();
        var notificationService = new Mock<ISecurityNotificationService>();
        notificationService
            .Setup(n => n.NotifyAsync(It.IsAny<SecurityNotification>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SecurityNotificationResult.Success());
        identityRepository.ConsumeSucceeds = consumeSucceeds;

        var uriValidator = new Mock<IUriValidator>();
        uriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(true);

        var dependencies = new EmailChangeDependencies(
            new IdentityContext(identityRepository, Mock.Of<IIdentityService>(), transactionProvider),
            new SecureTokenContext(tokenGenerator, tokenHasher),
            new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator.Object),
            sessionRepository,
            resolvedSecretProtector,
            new IdentityAuditContext(time, audit, notificationService.Object));
        var service = new EmailChangeService(dependencies);

        return new Fixture(service, identityRepository, emailSender, audit, resolvedSecretProtector, sessionRepository, notificationService, uriValidator);
    }

    private sealed record Fixture(EmailChangeService Service, InMemoryIdentityRepository IdentityRepository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, ISecretProtector SecretProtector, StubSessionRepository SessionRepository, Mock<ISecurityNotificationService> NotificationService, Mock<IUriValidator> UriValidator);

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed) : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            var allowed = attempt.Purpose == "email-change-request" ? requestAllowed : verifyAllowed;
            return Task.FromResult(new RateLimitDecision
            {
                Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
                Remaining = allowed ? 1 : 0,
                WindowResetAt = DateTimeOffset.UtcNow.Add(rule.Window)
            });
        }
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }
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

    private sealed class FakeSecretProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => data;
        public byte[] Unprotect(byte[] data) => data;
        public string Protect(string plaintext) => "protected:" + plaintext;
        public string Unprotect(string protectedText) => protectedText.Replace("protected:", "");
    }

    private sealed class ThrowingSecretProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => data;
        public byte[] Unprotect(byte[] data) => throw new InvalidOperationException();
        public string Protect(string plaintext) => "protected:" + plaintext;
        public string Unprotect(string protectedText) => throw new InvalidOperationException();
    }

    private sealed class StubSessionRepository : IAuthenticationSessionRepository
    {
        public Guid? RevokedUserId { get; private set; }
        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            RevokedUserId = userId;
            return Task.FromResult(1);
        }

        public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    }

    private sealed class InMemoryIdentityRepository : IIdentityRepository
    {
        public List<IUser> Users { get; } = [];
        public List<UserCredential> Credentials { get; } = [];
        public bool ConsumeSucceeds { get; set; } = true;

        public InMemoryIdentityRepository(params IUser?[] users)
        {
            Users.AddRange(users.OfType<IUser>());
        }

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
            return Task.FromResult(Users.SingleOrDefault(u => string.Equals(IdentityNormalization.NormalizeEmail(u.Email), normalizedEmail, StringComparison.OrdinalIgnoreCase) && (u as ITenantUser)?.TenantId == tenantId));
        }
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult(Users.SingleOrDefault(u => u.Id == userId));
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            var existing = Users.Single(u => u.Id == user.Id);
            switch (existing)
            {
                case AshlarUser ashlarUser:
                    var updatedAshlar = ashlarUser with { Email = user.Email, EmailVerifiedAt = user.EmailVerifiedAt };
                    Users.Remove(ashlarUser);
                    Users.Add(updatedAshlar);
                    break;
                case MetadataUser metadataUser:
                    metadataUser.Email = user.Email;
                    metadataUser.EmailVerifiedAt = user.EmailVerifiedAt;
                    break;
            }
            _ = user.Name;
            _ = user.IsActive;
            _ = (user as ITenantUser)?.TenantId;
            _ = (user as IHasAuditMetadata)?.CreatedAt;
            if (user is IHasAuditMetadata metadata)
            {
                metadata.UpdatedAt = DateTimeOffset.UtcNow;
                _ = metadata.UpdatedAt;
            }
            return Task.CompletedTask;
        }

        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Credentials.SingleOrDefault(c => c.UserId == userId && c.ProviderType == type && c.ProviderName == providerName && (providerKey == null || c.ProviderKey == providerKey)));
        }

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
        {
            Credentials.Add(credential);
            return Task.CompletedTask;
        }
        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default)
        {
            if (!ConsumeSucceeds) return Task.FromResult(false);
            var credential = Credentials.SingleOrDefault(c => c.Id == credentialId && c.Version == expectedVersion);
            if (credential == null) return Task.FromResult(false);
            Credentials.Remove(credential);
            return Task.FromResult(true);
        }
        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
        {
            var toRevoke = Credentials.Where(c => c.UserId == userId && c.ProviderType == type && c.ProviderName == providerName && c.RevokedAt == null).ToList();
            foreach (var c in toRevoke) c.RevokedAt = DateTimeOffset.UtcNow;
            return Task.FromResult(toRevoke.Count);
        }
    }

    private sealed class MetadataUser : IUser, IHasAuditMetadata
    {
        public required Guid Id { get; init; }
        public required string Email { get; set; }
        public string? Name { get; set; }
        public bool IsActive { get; set; }
        public DateTimeOffset? EmailVerifiedAt { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
    }
}
