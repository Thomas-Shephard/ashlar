using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

public sealed class EmailVerificationServiceTests
{
    private readonly AshlarUser _user = new() { Id = Guid.NewGuid(), Email = "user@example.com", IsActive = true };

    [Test]
    public void ConstructorUsesDefaultOptionsWhenOptionsAreNull()
    {
        var identityContext = new IdentityContext(new InMemoryIdentityRepository(), Mock.Of<IIdentityService>(), new NullTransactionProvider());
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
        var credential = fixture.IdentityRepository.Credentials.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo(_user.Email));
            Assert.That(credential.UserId, Is.EqualTo(_user.Id));
            Assert.That(credential.Purpose, Is.EqualTo("email-verification"));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationRequested), Is.True);
        }
    }

    [Test]
    public async Task RequestVerificationSucceedsIfAlreadyVerified()
    {
        var verifiedUser = new AshlarUser { Id = Guid.NewGuid(), Email = "verified@example.com", IsActive = true, EmailVerifiedAt = DateTimeOffset.UtcNow };
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
            Assert.That(result.ErrorMessage, Is.EqualTo("User not found or inactive."));
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
    public async Task VerifyTokenSucceedsAndUpdatesUser()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.VerifyTokenAsync(_user.Id, token);
        var updatedUser = await fixture.IdentityRepository.GetUserByIdAsync(_user.Id);

        Assert.That(updatedUser, Is.Not.Null);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(updatedUser.EmailVerifiedAt, Is.Not.Null);
            Assert.That(fixture.IdentityRepository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerified), Is.True);
        }
    }

    [Test]
    public async Task VerifyTokenPreservesAuditMetadataForMetadataBackedUser()
    {
        var user = new MetadataUser { Id = Guid.NewGuid(), Email = "user@example.com", IsActive = true, CreatedAt = DateTimeOffset.UtcNow.AddDays(-1) };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.VerifyTokenAsync(user.Id, token);

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
        var result = await fixture.Service.VerifyTokenAsync(_user.Id, "invalid-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid or expired token."));
        }
    }

    [Test]
    public async Task VerifyTokenFailsForExpiredToken()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.Time.Advance(TimeSpan.FromDays(2));

        var result = await fixture.Service.VerifyTokenAsync(_user.Id, token);

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task VerifyTokenFailsIfCredentialWasConsumedConcurrently()
    {
        var fixture = CreateFixture(_user, consumeSucceeds: false);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("https://example.com/callback") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());

        var result = await fixture.Service.VerifyTokenAsync(_user.Id, token);

        Assert.That(result.ErrorMessage, Is.EqualTo("Invalid or expired token."));
    }

    [Test]
    public async Task VerifyTokenFailsIfUserNoLongerExists()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestVerificationAsync(new EmailVerificationRequest { UserId = _user.Id, CallbackBaseUri = new Uri("http://localhost") });
        var token = ExtractToken(fixture.EmailSender.Messages.Single());
        fixture.IdentityRepository.Users.Clear();

        var result = await fixture.Service.VerifyTokenAsync(_user.Id, token);

        Assert.That(result.ErrorMessage, Is.EqualTo("Invalid or expired token."));
    }

    [Test]
    public async Task VerifyTokenRateLimits()
    {
        var fixture = CreateFixture(_user, verifyAllowed: false);
        var result = await fixture.Service.VerifyTokenAsync(_user.Id, "some-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailVerificationVerificationRateLimited), Is.True);
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
            Assert.That(result.ErrorMessage, Contains.Substring("not allowed"));
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
        var identityRepository = new InMemoryIdentityRepository(user);
        var audit = new RecordingSecurityEventSink();
        var emailSender = new RecordingEmailSender();
        var tokenHasher = new Sha256TokenHasher();
        var tokenGenerator = new SecureTokenGenerator();
        var transactionProvider = new NullTransactionProvider();
        var rateLimiter = new StubRateLimiter(requestAllowed, verifyAllowed);
        identityRepository.ConsumeSucceeds = consumeSucceeds;

        var uriValidator = new Mock<IUriValidator>();
        uriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(true);

        var service = new EmailVerificationService(
            new EmailVerificationServiceDependencies(
                new IdentityContext(identityRepository, Mock.Of<IIdentityService>(), transactionProvider),
                new SecureTokenContext(tokenGenerator, tokenHasher),
                new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator.Object),
                new IdentityAuditContext(time, audit)));

        return new Fixture(service, identityRepository, emailSender, audit, time, tokenHasher, rateLimiter, uriValidator);
    }

    private sealed record Fixture(EmailVerificationService Service, InMemoryIdentityRepository IdentityRepository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time, ISecureTokenHasher TokenHasher, StubRateLimiter RateLimiter, Mock<IUriValidator> UriValidator);

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed) : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            var allowed = attempt.Purpose == "email-verification-request" ? requestAllowed : verifyAllowed;
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

    private sealed class InMemoryIdentityRepository : IIdentityRepository
    {
        public List<IUser> Users { get; } = [];
        public List<UserCredential> Credentials { get; } = [];
        public bool ConsumeSucceeds { get; set; } = true;

        public InMemoryIdentityRepository(IUser? user = null)
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
