using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Email;

internal sealed class EmailVerificationServiceTests
{
    private readonly AshlarUser _user = new() { Id = Guid.NewGuid(), Email = "user@example.com", AccountState = UserAccountState.Active };

    [Test]
    public void ConstructorUsesDefaultOptionsWhenOptionsAreNull()
    {
        var repository = new InMemoryUserCredentialStore();
        var identityContext = new IdentityContext(repository, repository, Mock.Of<IIdentityService>(), new NullTransactionProvider());
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher());
        var infrastructure = new IdentityInfrastructureContext(Mock.Of<IEmailSender>(), Mock.Of<IAuthenticationRateLimiter>(), Mock.Of<IUriValidator>());
        var audit = new IdentityAuditContext(new FakeTimeProvider(), new RecordingSecurityEventSink());

        var dependencies = new EmailVerificationServiceDependencies(identityContext, tokenContext, infrastructure, audit, options: null);
        var service = new EmailVerificationService(dependencies);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task RequestVerificationSendsEmailAndStoresCredential()
    {
        var fixture = CreateFixture(_user);
        var request = new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") };

        var result = await fixture.Service.RequestVerificationAsync(request);

        Assert.That(result.Succeeded, Is.True);
        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.UserCredentialStore.Credentials.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo(_user.Email));
            Assert.That(credential.UserId, Is.EqualTo(_user.Id));
            Assert.That(credential.Purpose, Is.EqualTo("email-verification"));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationRequested), Is.True);
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task RequestVerificationPropagatesAuditMetadataToSecurityEvent()
    {
        var actorUserId = Guid.NewGuid();
        var fixture = CreateFixture(_user);
        var audit = new AuditContext(actorUserId, "203.0.113.10", "NUnit", "corr-verify");
        var request = new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback"), Audit = audit };

        var result = await fixture.Service.RequestVerificationAsync(request);
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationRequested);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(securityEvent.ActorUserId, Is.EqualTo(actorUserId));
            Assert.That(securityEvent.IpAddress, Is.EqualTo(audit.IpAddress));
            Assert.That(securityEvent.UserAgent, Is.EqualTo(audit.UserAgent));
            Assert.That(securityEvent.CorrelationId, Is.EqualTo(audit.CorrelationId));
        }
    }

    [Test]
    public async Task RequestVerificationSucceedsIfAlreadyVerified()
    {
        var verifiedUser = new AshlarUser { Id = Guid.NewGuid(), Email = "verified@example.com", AccountState = UserAccountState.Active, EmailVerifiedAt = DateTimeOffset.UtcNow };
        var fixture = CreateFixture(verifiedUser);
        var request = new EmailVerificationRequest { UserId = verifiedUser.Id, CallbackBaseUri = new Uri("https://example.com/callback") };

        var result = await fixture.Service.RequestVerificationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
        }
    }

    [Test]
    public async Task RequestVerificationFailsIfUserNotFound()
    {
        var fixture = CreateFixture();
        var request = new EmailVerificationRequest { UserId = Guid.NewGuid(), CallbackBaseUri = new Uri("https://example.com/callback") };

        var result = await fixture.Service.RequestVerificationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }
    }

    [Test]
    public async Task RequestVerificationRateLimits()
    {
        var fixture = CreateFixture(_user, requestAllowed: false);
        var request = new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") };

        var result = await fixture.Service.RequestVerificationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationRateLimited), Is.True);
        }
    }

    [Test]
    public async Task RequestVerificationRateLimitWorksForNonTenantUser()
    {
        var user = new MetadataUser { Id = Guid.NewGuid(), Email = "user@example.com", AccountState = UserAccountState.Active };
        var fixture = CreateFixture(user, requestAllowed: false);
        var request = new EmailVerificationRequest { UserId = user.Id, CallbackBaseUri = new Uri("https://example.com/callback") };

        var result = await fixture.Service.RequestVerificationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationRateLimited).TenantId, Is.Null);
        }
    }

    [Test]
    public async Task VerifyTokenSucceedsAndUpdatesUser()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = token });
        var updatedUser = await fixture.UserCredentialStore.GetUserByIdAsync(_user.Id);

        Assert.That(updatedUser, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(updatedUser.EmailVerifiedAt, Is.Not.Null);
            Assert.That(fixture.UserCredentialStore.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerified), Is.True);
        }
    }

    [Test]
    public async Task VerifyTokenIncludesTenantIdInSecurityEvent()
    {
        var tenantId = Guid.NewGuid();
        var user = _user with { TenantId = tenantId };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.Audit.Events.Clear();

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = user.Id, Token = token });
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailVerified);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(securityEvent.TenantId, Is.EqualTo(tenantId));
        }
    }

    [Test]
    public async Task VerifyTokenPreservesAuditMetadataForMetadataBackedUser()
    {
        var user = new MetadataUser { Id = Guid.NewGuid(), Email = "user@example.com", AccountState = UserAccountState.Active, CreatedAt = DateTimeOffset.UtcNow.AddDays(-1) };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(user.EmailVerifiedAt, Is.Not.Null);
            Assert.That(user.UpdatedAt, Is.Not.Null);
        }
    }

    [Test]
    public async Task VerifyTokenFailsForInvalidToken()
    {
        var fixture = CreateFixture(_user);
        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = "invalid-token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
        }
    }

    [Test]
    public async Task VerifyTokenReturnsInvalidOrExpiredForOverlongTokenWithoutMutatingState()
    {
        var user = new AshlarUser { Id = Guid.NewGuid(), Email = "user@example.com", AccountState = UserAccountState.Active };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        fixture.Audit.Events.Clear();

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = user.Id, Token = new string('a', 257) });
        var unchangedUser = await fixture.UserCredentialStore.GetUserByIdAsync(user.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(unchangedUser?.EmailVerifiedAt, Is.Null);
            Assert.That(fixture.UserCredentialStore.Credentials.Single().Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationFailed).FailureReason, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken.Value));
        }
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task VerifyTokenReturnsInvalidOrExpiredForMissingTokenWithoutMutatingState(string? token)
    {
        var user = new AshlarUser { Id = Guid.NewGuid(), Email = "user@example.com", AccountState = UserAccountState.Active };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        fixture.Audit.Events.Clear();

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = user.Id, Token = token! });
        var unchangedUser = await fixture.UserCredentialStore.GetUserByIdAsync(user.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(unchangedUser?.EmailVerifiedAt, Is.Null);
            Assert.That(fixture.UserCredentialStore.Credentials.Single().Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationFailed).FailureReason, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken.Value));
        }
    }

    [Test]
    public async Task VerifyTokenFailsForExpiredToken()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.Time.Advance(TimeSpan.FromDays(2));

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = token });

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task VerifyTokenFailsIfCredentialWasConsumedConcurrently()
    {
        var fixture = CreateFixture(_user, consumeSucceeds: false);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.TokenConsumptionFailed));
        }
    }

    [Test]
    public async Task VerifyTokenFailsIfUserNoLongerExists()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("http://localhost") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.UserCredentialStore.Users.Clear();

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }
    }

    [Test]
    public async Task VerifyTokenRateLimits()
    {
        var fixture = CreateFixture(_user, verifyAllowed: false);
        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = "some-token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationVerificationRateLimited), Is.True);
        }
    }

    [Test]
    public async Task VerifyTokenChecksSourceTokenAndUserBuckets()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("http://localhost") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.RateLimiter.Attempts.Clear();

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest
        {
            UserId = _user.Id,
            Token = token,
            Audit = new AuditContext(Guid.NewGuid(), "203.0.113.99", "NUnit", "corr-confirm")
        });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.RateLimiter.Attempts, Has.Count.EqualTo(3));
            Assert.That(fixture.RateLimiter.Attempts.Select(a => a.Purpose), Is.All.EqualTo("email-verification-verify"));
            Assert.That(fixture.RateLimiter.Attempts.Select(a => a.IpAddress), Is.All.EqualTo("203.0.113.99"));
            Assert.That(fixture.RateLimiter.Attempts.Select(a => a.Key), Is.Unique);
            Assert.That(string.Join("|", fixture.RateLimiter.Attempts.Select(a => a.Key)), Does.Not.Contain(token));
        }
    }

    [Test]
    public async Task VerifyTokenStopsWhenTokenBucketIsRateLimited()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("http://localhost") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.RateLimiter.Attempts.Clear();
        fixture.RateLimiter.BlockedVerifyCallNumber = 2;

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.RateLimiter.Attempts, Has.Count.EqualTo(2));
            Assert.That(fixture.UserCredentialStore.Credentials.Single().Status, Is.EqualTo(CredentialStatus.Active));
        }
    }

    [Test]
    public async Task VerifyTokenStopsWhenUserBucketIsRateLimited()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("http://localhost") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.RateLimiter.Attempts.Clear();
        fixture.RateLimiter.BlockedVerifyCallNumber = 3;

        var result = await fixture.Service.ConfirmVerificationAsync(new ConfirmEmailVerificationRequest { UserId = _user.Id, Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.RateLimiter.Attempts, Has.Count.EqualTo(3));
            Assert.That(fixture.UserCredentialStore.Credentials.Single().Status, Is.EqualTo(CredentialStatus.Active));
        }
    }

    [Test]
    public async Task RequestVerificationFailsForInvalidCallbackUri()
    {
        var fixture = CreateFixture(_user);
        fixture.UriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(false);
        var request = new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://evil.com") };

        var result = await fixture.Service.RequestVerificationAsync(request);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureReason, Contains.Substring("not allowed"));
        }
    }

    private static string ExtractToken(EmailMessage message)
    {
        var body = message.TextBody!;
        var uri = new Uri(body.Split(": ").Last());
        return System.Web.HttpUtility.ParseQueryString(uri.Query)["t"]!;
    }

    private static Fixture CreateFixture(IUser? user = null, bool requestAllowed = true, bool verifyAllowed = true, bool consumeSucceeds = true)
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 9, 12, 0, 0, TimeSpan.Zero));
        var UserCredentialStore = new InMemoryUserCredentialStore(user);
        var audit = new RecordingSecurityEventSink();
        var emailSender = new RecordingEmailSender();
        var tokenHasher = new Sha256TokenHasher();
        var tokenGenerator = new SecureTokenGenerator();
        var transactionProvider = new NullTransactionProvider();
        var rateLimiter = new StubRateLimiter(requestAllowed, verifyAllowed);
        UserCredentialStore.ConsumeSucceeds = consumeSucceeds;

        var uriValidator = new Mock<IUriValidator>();
        uriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(true);

        var service = new EmailVerificationService(
            new EmailVerificationServiceDependencies(
                new IdentityContext(UserCredentialStore, UserCredentialStore, Mock.Of<IIdentityService>(), transactionProvider),
                new SecureTokenContext(tokenGenerator, tokenHasher),
                new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator.Object),
                new IdentityAuditContext(time, audit)));

        return new Fixture(service, UserCredentialStore, emailSender, audit, time, tokenHasher, rateLimiter, uriValidator);
    }

    private sealed record Fixture(EmailVerificationService Service, InMemoryUserCredentialStore UserCredentialStore, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time, ISecureTokenHasher TokenHasher, StubRateLimiter RateLimiter, Mock<IUriValidator> UriValidator);

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed) : IAuthenticationRateLimiter
    {
        private int _verifyCalls;

        public List<RateLimitAttempt> Attempts { get; } = [];

        public int? BlockedVerifyCallNumber { get; set; }

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            Attempts.Add(attempt);
            var allowed = attempt.Purpose == "email-verification-request" ? requestAllowed : IsVerifyAllowed();
            return Task.FromResult(new RateLimitDecision
            {
                Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
                Remaining = allowed ? 1 : 0,
                WindowResetAt = DateTimeOffset.UtcNow.Add(rule.Window)
            });
        }

        private bool IsVerifyAllowed()
        {
            _verifyCalls++;
            return verifyAllowed && _verifyCalls != BlockedVerifyCallNumber;
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

    private sealed class InMemoryUserCredentialStore : IUserRepository, ICredentialRepository
    {
        public List<IUser> Users { get; } = [];
        public List<UserCredential> Credentials { get; } = [];
        public bool ConsumeSucceeds { get; set; } = true;

        public InMemoryUserCredentialStore(IUser? user = null)
        {
            if (user != null) Users.Add(user);
        }

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(Users.SingleOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)));
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(Users.SingleOrDefault(u => u.Id == userId));
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
            _ = user.CanSignIn();
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
        public Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<UserCredential>>([]);
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
        public UserAccountState AccountState { get; set; }
        public DateTimeOffset? EmailVerifiedAt { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
    }
}
