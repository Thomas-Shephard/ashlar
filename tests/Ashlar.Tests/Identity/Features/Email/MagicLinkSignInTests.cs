using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Email;

internal sealed class MagicLinkSignInTests
{
    private readonly User _user = new() { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), Email = "user@example.com", IsActive = true };

    [Test]
    public async Task RequestLinkSendsEmailAndStoresHashedCredentialForActiveUser()
    {
        var fixture = CreateFixture(_user);
        var baseUri = new Uri("https://myapp.com/verify");

        await fixture.Service.RequestLinkAsync(" User@Example.com ", baseUri, new AuthenticationContext(IpAddress: "127.0.0.1", CorrelationId: "corr"));

        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.Repository.Credentials.Single();

        Assert.That(message.TextBody, Is.Not.Null);
        var token = ExtractToken(message.TextBody);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("USER@EXAMPLE.COM"));
            Assert.That(credential.ProviderType, Is.EqualTo(ProviderType.MagicLink));
            Assert.That(credential.ProviderName, Is.EqualTo(ProviderType.MagicLink.Value));
            Assert.That(credential.ProviderKey, Is.EqualTo(fixture.TokenHasher.HashToken(token)));
            Assert.That(credential.Purpose, Is.EqualTo("magic-link-sign-in"));
            Assert.That(credential.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(credential.ExpiresAt, Is.EqualTo(fixture.Time.GetUtcNow().AddMinutes(10)));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.MagicLinkRequested), Is.True);
            Assert.That(message.TextBody, Does.Contain($"token={token}"));
            Assert.That(message.TextBody, Does.Not.Contain("USER@EXAMPLE.COM"));
        }
    }

    [Test]
    public async Task RequestLinkDoesNotRevealOrSendForMissingUser()
    {
        var fixture = CreateFixture();

        await fixture.Service.RequestLinkAsync("missing@example.com", new Uri("https://myapp.com/verify"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkRequestSuppressed));
            Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo("user_missing"));
        }
    }

    [Test]
    public void RequestLinkRejectsDisallowedCallbackBeforeGeneratingToken()
    {
        var fixture = CreateFixture(_user, callbackAllowed: false);

        var ex = Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://evil.example/verify")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ex?.ParamName, Is.EqualTo("uri"));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
        }
    }

    [Test]
    public async Task RequestLinkDoesNotSendForInactiveUser()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "inactive@example.com", IsActive = false };
        var fixture = CreateFixture(user);

        await fixture.Service.RequestLinkAsync(user.Email, new Uri("https://myapp.com/verify"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo("user_disabled"));
        }
    }

    [Test]
    public async Task RequestRateLimitBlocksSending()
    {
        var fixture = CreateFixture(_user, requestAllowed: false);

        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://myapp.com/verify"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkRequestRateLimited));
        }
    }

    [Test]
    public async Task VerifyLinkSucceedsAndConsumesCredential()
    {
        var fixture = CreateFixture(_user);
        var baseUri = new Uri("https://myapp.com/verify?existing=val");
        await fixture.Service.RequestLinkAsync(_user.Email, baseUri);

        var message = fixture.EmailSender.Messages.Single();
        Assert.That(message.TextBody, Is.Not.Null);
        var token = ExtractToken(message.TextBody);

        var response = await fixture.Service.VerifyLinkAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.True);
            Assert.That(response.User?.Id, Is.EqualTo(_user.Id));
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.AuthenticationSucceeded), Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.CredentialConsumed), Is.True);
        }
    }

    [Test]
    public async Task RequestLinkRevokesPreviousLinks()
    {
        var fixture = CreateFixture(_user);
        var baseUri = new Uri("https://myapp.com/verify");

        // Request first link
        await fixture.Service.RequestLinkAsync(_user.Email, baseUri);
        var firstToken = ExtractToken(fixture.EmailSender.Messages[0].TextBody);

        // Request second link
        await fixture.Service.RequestLinkAsync(_user.Email, baseUri);
        var secondToken = ExtractToken(fixture.EmailSender.Messages[1].TextBody);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(2));
            Assert.That(fixture.Repository.Credentials.Count(c => c.Status == CredentialStatus.Revoked), Is.EqualTo(1));
            Assert.That(fixture.Repository.Credentials.Single(c => c.Status == CredentialStatus.Active).ProviderKey, Is.EqualTo(fixture.TokenHasher.HashToken(secondToken)));

            // First token should fail (already revoked)
            var response1 = await fixture.Service.VerifyLinkAsync(firstToken);
            Assert.That(response1.Succeeded, Is.False);

            // Second token should succeed
            var response2 = await fixture.Service.VerifyLinkAsync(secondToken);
            Assert.That(response2.Succeeded, Is.True);
        }
    }

    [Test]
    public async Task VerifyLinkFailsForWrongToken()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://myapp.com/verify"));

        var response = await fixture.Service.VerifyLinkAsync("wrong-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.AuthenticationFailed), Is.True);
        }
    }

    [Test]
    public async Task VerifyLinkFailsForOverlongTokenWithoutHashing()
    {
        var fixture = CreateFixture(_user);
        var token = new string('a', 257);

        var response = await fixture.Service.VerifyLinkAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(fixture.RateLimiter.Attempts, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationFailed));
        }
    }

    [Test]
    public async Task VerifyLinkFailsForExpiredCredential()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://myapp.com/verify"));

        var message = fixture.EmailSender.Messages.Single();
        Assert.That(message.TextBody, Is.Not.Null);
        var token = ExtractToken(message.TextBody);
        fixture.Time.Advance(TimeSpan.FromMinutes(11));

        var response = await fixture.Service.VerifyLinkAsync(token);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public async Task VerifyRateLimitBlocksVerification()
    {
        var fixture = CreateFixture(_user, verifyAllowed: false);

        var response = await fixture.Service.VerifyLinkAsync("any-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited));
        }
    }

    [Test]
    public async Task VerifyLinkWithoutIpUsesTokenScopedRateLimitKey()
    {
        var fixture = CreateFixture(_user);

        await fixture.Service.VerifyLinkAsync("attempt-token");

        Assert.That(fixture.RateLimiter.Attempts.Single(a => a.Purpose == "magic-link-verify").Key, Is.EqualTo($"magic-link-verify:token:{fixture.TokenHasher.HashToken("attempt-token")}"));
    }

    [Test]
    public async Task VerifyLinkWithIpUsesIpScopedRateLimitKey()
    {
        var fixture = CreateFixture(_user);
        var context = new AuthenticationContext(IpAddress: "127.0.0.1", CorrelationId: "corr");

        await fixture.Service.VerifyLinkAsync("attempt-token", context);

        Assert.That(fixture.RateLimiter.Attempts.Single(a => a.Purpose == "magic-link-verify").Key, Is.EqualTo("magic-link-verify:127.0.0.1"));
    }

    [Test]
    public async Task VerifyLinkWithoutIpUsesCorrelationScopedRateLimitKey()
    {
        var fixture = CreateFixture(_user);
        var context = new AuthenticationContext(CorrelationId: "corr");

        await fixture.Service.VerifyLinkAsync("attempt-token", context);

        Assert.That(fixture.RateLimiter.Attempts.Single(a => a.Purpose == "magic-link-verify").Key, Is.EqualTo("magic-link-verify:correlation:corr"));
    }

    [Test]
    public async Task ProviderRejectsWrongAssertionTypeAndUsesExpectedIdentity()
    {
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        var assertion = new LocalPasswordAssertion("pw");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.Key, Is.EqualTo(AuthenticationProviderKey.MagicLink));
            Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateAsync(assertion, null));
            Assert.That(provider.GetProviderKey(assertion, Guid.NewGuid()), Is.Empty);

            var user = await provider.FindUserAsync(assertion, new AuthenticationContext(), new InMemoryIdentityRepository());
            Assert.That(user, Is.Null);
        }
    }

    [Test]
    public void ProviderConstructorRequiresTokenHasher()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkAuthenticationProvider(null!));
    }

    [Test]
    public async Task ProviderFailsWrongPurposeCredential()
    {
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        var assertion = new MagicLinkAssertion("token");
        var wrongPurpose = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.MagicLink,
            ProviderName = ProviderType.MagicLink.Value,
            ProviderKey = tokenHasher.HashToken("token"),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Purpose = "other"
        };

        var result = await provider.AuthenticateAsync(assertion, wrongPurpose);

        Assert.That(result.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
    }

    [Test]
    public async Task EmailSubjectAndBodyOptionsAreApplied()
    {
        var fixture = CreateFixture(_user, options: new MagicLinkSignInOptions
        {
            EmailSubject = "Custom",
            EmailTextTemplate = "Link={0}"
        });

        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://myapp.com/verify"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages.Single().Subject, Is.EqualTo("Custom"));
            Assert.That(fixture.EmailSender.Messages.Single().TextBody, Does.Contain("Link=https://myapp.com"));
            Assert.That(fixture.EmailSender.Messages.Single().TextBody, Does.Contain("/verify?token="));
        }
    }

    [Test]
    public void MagicLinkAssertionValidatesToken()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => _ = new MagicLinkAssertion(" "));
            Assert.That(new MagicLinkAssertion("token").Token, Is.EqualTo("token"));
        }
    }

    [Test]
    public void RequestLinkValidatesArguments()
    {
        var fixture = CreateFixture(_user);

        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.RequestLinkAsync(_user.Email, null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestLinkAsync(" ", new Uri("https://myapp.com/verify")));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.VerifyLinkAsync(" "));
        }
    }

    [Test]
    public void ServiceConstructorRequiresDependencies()
    {
        var repository = new InMemoryIdentityRepository(_user);
        var identity = Mock.Of<IIdentityService>();
        var emailSender = new RecordingEmailSender();
        var rateLimiter = new StubRateLimiter(true, true, TimeProvider.System);
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher());
        var uriValidator = Mock.Of<IUriValidator>();
        var provider = new MagicLinkAuthenticationProvider(tokenContext.Hasher);
        var core = new IdentityContext(repository, identity, new NullTransactionProvider());
        var infrastructure = new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator);
        var audit = new IdentityAuditContext(TimeProvider.System, Mock.Of<ISecurityEventSink>());
        var dependencies = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, audit);

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrow(() => _ = new MagicLinkSignInService(dependencies));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInService(null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void DependenciesRequireRequiredServices()
    {
        var repository = new InMemoryIdentityRepository(_user);
        var identity = Mock.Of<IIdentityService>();
        var core = new IdentityContext(repository, identity, new NullTransactionProvider());
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher());
        var infrastructure = new IdentityInfrastructureContext(Mock.Of<IEmailSender>(), Mock.Of<IAuthenticationRateLimiter>(), Mock.Of<IUriValidator>());
        var provider = new MagicLinkAuthenticationProvider(tokenContext.Hasher);
        var audit = new IdentityAuditContext(TimeProvider.System, Mock.Of<ISecurityEventSink>());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(null!, tokenContext, infrastructure, provider, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, null!, infrastructure, provider, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, null!, provider, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, null!, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, null!));
        }
    }

    [Test]
    public void ProviderExposesTypicalCredentialLengthAndPreservesPreparedValue()
    {
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.TypicalCredentialLength, Is.EqualTo(71));
            Assert.That(provider.PrepareCredentialValue(new MagicLinkAssertion("t"), "val"), Is.EqualTo("val"));
        }
    }

    [Test]
    public void AddAshlarMagicLinkSignInResolvesServiceAndProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IIdentityRepository>(new InMemoryIdentityRepository(_user));
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton<IEmailSender, RecordingEmailSender>();
        services.AddAshlarMagicLinkSignIn(options => options.EmailSubject = "Modified");

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IMagicLinkSignInService>(), Is.TypeOf<MagicLinkSignInService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IEnumerable<IAuthenticationProvider>>().Any(p => p.Key == AuthenticationProviderKey.MagicLink), Is.True);
        }
    }

    [Test]
    public void AddAshlarMagicLinkSignInDoesNotRegisterTotpOptionsValidation()
    {
        var services = new ServiceCollection();
        services.Configure<TotpOptions>(options => options.CodeDigits = 5);

        services.AddAshlarMagicLinkSignIn();

        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<TotpOptions>>().Value;

        Assert.That(options.CodeDigits, Is.EqualTo(5));
    }

    private static Fixture CreateFixture(User? user = null, bool requestAllowed = true, bool verifyAllowed = true, MagicLinkSignInOptions? options = null, bool callbackAllowed = true)
    {
        var repository = new InMemoryIdentityRepository(user);
        var audit = new RecordingSecurityEventSink();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 3, 12, 0, 0, TimeSpan.Zero));
        var emailSender = new RecordingEmailSender();
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        var registry = new AuthenticationProviderRegistry([provider]);
        var transactionProvider = new NullTransactionProvider();
        var credentialService = new CredentialService(
            repository,
            Mock.Of<ISecretProtector>(),
            transactionProvider,
            new CredentialServiceDependencies(TimeProvider: time, SecurityEventSink: audit));
        var pipeline = new AuthenticationPipeline(registry, credentialService, transactionProvider, audit, time);
        var identity = new IdentityService(repository, registry, credentialService, pipeline, transactionProvider, audit, time);
        var core = new IdentityContext(repository, identity, transactionProvider);
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), tokenHasher);
        var rateLimiter = new StubRateLimiter(requestAllowed, verifyAllowed, time);
        var uriValidator = new Mock<IUriValidator>();
        if (!callbackAllowed)
        {
            uriValidator
                .Setup(v => v.ValidateOrThrow(It.IsAny<Uri?>()))
                .Throws((Uri? uri) => new ArgumentException("The URI is not allowed.", nameof(uri)));
        }

        var infrastructure = new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator.Object);
        var auditContext = new IdentityAuditContext(time, audit);

        var dependencies = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, auditContext);
        var service = new MagicLinkSignInService(dependencies, Options.Create(options ?? new MagicLinkSignInOptions()));
        return new Fixture(service, repository, emailSender, audit, time, tokenHasher, rateLimiter);
    }

    private static string ExtractToken(string? body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var uri = new Uri(body.Split(' ').Last());
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        return query["token"] ?? throw new AssertionException("Token not found in email body.");
    }

    private sealed record Fixture(MagicLinkSignInService Service, InMemoryIdentityRepository Repository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time, ISecureTokenHasher TokenHasher, StubRateLimiter RateLimiter);

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed, TimeProvider timeProvider) : IAuthenticationRateLimiter
    {
        public List<RateLimitAttempt> Attempts { get; } = [];

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            Attempts.Add(attempt);
            var allowed = attempt.Purpose == "magic-link-request" ? requestAllowed : verifyAllowed;
            return Task.FromResult(new RateLimitDecision
            {
                Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
                Remaining = allowed ? 1 : 0,
                WindowResetAt = timeProvider.GetUtcNow().Add(rule.Window)
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

    private sealed class InMemoryIdentityRepository(params User?[] users) : IIdentityRepository
    {
        private readonly List<User> _users = users.OfType<User>().ToList();
        public List<UserCredential> Credentials { get; } = [];

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(_users.SingleOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)));
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(_users.SingleOrDefault(u => u.Id == userId));
        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default) => Task.FromResult(Credentials.SingleOrDefault(c => c.UserId == userId && c.ProviderType == type && string.Equals(c.ProviderName, providerName, StringComparison.OrdinalIgnoreCase) && (providerKey == null || c.ProviderKey == providerKey))?.Clone());

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
        {
            var credential = Credentials.SingleOrDefault(c => c.ProviderType == type && string.Equals(c.ProviderName, providerName, StringComparison.OrdinalIgnoreCase) && c.ProviderKey == providerKey);
            return Task.FromResult<IUser?>(credential == null ? null : _users.SingleOrDefault(u => u.Id == credential.UserId));
        }

        public Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<UserCredential>>([]);
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) { _users.Add((User)user); return Task.CompletedTask; }
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) { Credentials.Add(credential); return Task.CompletedTask; }
        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
        {
            Credentials.RemoveAll(c => c.ProviderType == credential.ProviderType && string.Equals(c.ProviderName, credential.ProviderName, StringComparison.OrdinalIgnoreCase) && c.ProviderKey == credential.ProviderKey);
            Credentials.Add(credential);
            return Task.CompletedTask;
        }
        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default)
        {
            var removed = Credentials.RemoveAll(c => c.Id == credentialId && c.Version == expectedVersion) == 1;
            return Task.FromResult(removed);
        }

        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
        {
            var count = 0;
            foreach (var c in Credentials.Where(c => c.UserId == userId && c.ProviderType == type && string.Equals(c.ProviderName, providerName, StringComparison.OrdinalIgnoreCase) && c.Status == CredentialStatus.Active))
            {
                c.Status = CredentialStatus.Revoked;
                c.RevokedAt = DateTimeOffset.UtcNow;
                count++;
            }
            return Task.FromResult(count);
        }
    }
}



