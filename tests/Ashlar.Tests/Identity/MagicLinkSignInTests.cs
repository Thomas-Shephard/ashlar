using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
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

namespace Ashlar.Tests.Identity;

public sealed class MagicLinkSignInTests
{
    private readonly User _user = new() { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), Email = "user@example.com", IsActive = true };

    [Test]
    public async Task RequestLinkSendsEmailAndStoresHashedCredentialForActiveUser()
    {
        var protector = new Mock<ISecretProtector>();
        protector.Setup(p => p.Protect(It.IsAny<string>())).Returns<string>(s => "protected_" + s);
        var fixture = CreateFixture(_user, secretProtector: protector.Object);
        var callbackUri = new Uri("https://example.com/signin?foo=bar");

        await fixture.Service.RequestLinkAsync(" User@Example.com ", callbackUri, new AuthenticationContext(IpAddress: "127.0.0.1", CorrelationId: "corr"));

        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.Repository.Credentials.Single();
        var link = ExtractLink(GetTextBody(message));
        var token = ExtractToken(link);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("USER@EXAMPLE.COM"));
            Assert.That(credential.ProviderType, Is.EqualTo(ProviderType.MagicLink));
            Assert.That(credential.ProviderName, Is.EqualTo(ProviderType.MagicLink.Value));
            Assert.That(credential.ProviderKey, Is.EqualTo(_user.Id.ToString("D")));
            Assert.That(credential.Purpose, Is.EqualTo("magic-link-sign-in"));
            Assert.That(credential.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(credential.CredentialValue, Is.EqualTo("protected_" + fixture.TokenHasher.HashToken(token)));
            Assert.That(credential.ExpiresAt, Is.EqualTo(fixture.Time.GetUtcNow().AddMinutes(10)));
            Assert.That(link, Does.Contain("foo=bar"));
            Assert.That(link, Does.Contain("email=USER%40EXAMPLE.COM"));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.MagicLinkRequested), Is.True);
            Assert.That(AllAuditText(fixture), Does.Not.Contain(token));
            Assert.That(AllAuditText(fixture), Does.Not.Contain("USER@EXAMPLE.COM"));
        }
    }

    [Test]
    public async Task RequestLinkDoesNotRevealOrSendForMissingUser()
    {
        var fixture = CreateFixture();

        await fixture.Service.RequestLinkAsync("missing@example.com", new Uri("https://example.com/"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkRequestSuppressed));
            Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo("user_missing"));
        }
    }

    [Test]
    public async Task RequestLinkDoesNotSendForInactiveUser()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "inactive@example.com", IsActive = false };
        var fixture = CreateFixture(user);

        await fixture.Service.RequestLinkAsync(user.Email, new Uri("https://example.com/"));

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

        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://example.com/"));

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
        var protector = new Mock<ISecretProtector>();
        protector.Setup(p => p.Protect(It.IsAny<string>())).Returns<string>(s => "protected_" + s);
        protector.Setup(p => p.Unprotect(It.Is<string>(s => s.StartsWith("protected_")))).Returns<string>(s => s.Substring("protected_".Length));

        var fixture = CreateFixture(_user, secretProtector: protector.Object);
        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://example.com/"));
        var link = ExtractLink(GetTextBody(fixture.EmailSender.Messages.Single()));
        var token = ExtractToken(link);

        var response = await fixture.Service.VerifyLinkAsync(_user.Email, token);

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
    public async Task VerifyLinkFailsForWrongToken()
    {
        var protector = new Mock<ISecretProtector>();
        protector.Setup(p => p.Protect(It.IsAny<string>())).Returns<string>(s => "protected_" + s);
        protector.Setup(p => p.Unprotect(It.Is<string>(s => s.StartsWith("protected_")))).Returns<string>(s => s.Substring("protected_".Length));

        var fixture = CreateFixture(_user, secretProtector: protector.Object);
        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://example.com/"));

        var response = await fixture.Service.VerifyLinkAsync(_user.Email, "wrong-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.AuthenticationFailed), Is.True);
        }
    }

    [Test]
    public async Task VerifyLinkFailsForExpiredCredential()
    {
        var protector = new Mock<ISecretProtector>();
        protector.Setup(p => p.Protect(It.IsAny<string>())).Returns<string>(s => "protected_" + s);
        protector.Setup(p => p.Unprotect(It.Is<string>(s => s.StartsWith("protected_")))).Returns<string>(s => s.Substring("protected_".Length));

        var fixture = CreateFixture(_user, secretProtector: protector.Object);
        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://example.com/"));
        var link = ExtractLink(GetTextBody(fixture.EmailSender.Messages.Single()));
        var token = ExtractToken(link);
        fixture.Time.Advance(TimeSpan.FromMinutes(11));

        var response = await fixture.Service.VerifyLinkAsync(_user.Email, token);

        Assert.That(response.Succeeded, Is.False);
    }

    [Test]
    public async Task VerifyRateLimitBlocksVerification()
    {
        var fixture = CreateFixture(_user, verifyAllowed: false);

        var response = await fixture.Service.VerifyLinkAsync(_user.Email, "some-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Succeeded, Is.False);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited));
        }
    }

    [Test]
    public void ProviderRejectsWrongAssertionTypeAndUsesExpectedIdentity()
    {
        var provider = new MagicLinkAuthenticationProvider(new Sha256TokenHasher());
        var assertion = new LocalPasswordAssertion("pw");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.Key, Is.EqualTo(AuthenticationProviderKey.MagicLink));
            Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateAsync(assertion, null));
        }
    }

    [Test]
    public async Task ProviderFindUserReturnsNullForWrongAssertionOrMissingEmail()
    {
        var provider = new MagicLinkAuthenticationProvider(new Sha256TokenHasher());
        var repository = new InMemoryIdentityRepository(_user);

        var wrongAssertion = await provider.FindUserAsync(new LocalPasswordAssertion("pw"), new AuthenticationContext(_user.Email), repository);
        var missingEmail = await provider.FindUserAsync(new MagicLinkAssertion("123"), new AuthenticationContext(" "), repository);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongAssertion, Is.Null);
            Assert.That(missingEmail, Is.Null);
        }
    }

    [Test]
    public async Task ProviderFailsMissingOrWrongPurposeCredential()
    {
        var provider = new MagicLinkAuthenticationProvider(new Sha256TokenHasher());
        var assertion = new MagicLinkAssertion("123");
        var missingValue = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.MagicLink,
            ProviderName = ProviderType.MagicLink.Value,
            ProviderKey = Guid.NewGuid().ToString("D"),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Purpose = "magic-link-sign-in"
        };
        var wrongPurpose = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.MagicLink,
            ProviderName = ProviderType.MagicLink.Value,
            ProviderKey = Guid.NewGuid().ToString("D"),
            Version = "v1",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            CredentialValue = "hash",
            Purpose = "other"
        };

        var missingValueResult = await provider.AuthenticateAsync(assertion, missingValue);
        var wrongPurposeResult = await provider.AuthenticateAsync(assertion, wrongPurpose);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingValueResult.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
            Assert.That(wrongPurposeResult.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
        }
    }

    [Test]
    public async Task EmailSubjectAndBodyOptionsAreApplied()
    {
        var fixture = CreateFixture(_user, options: new MagicLinkSignInOptions
        {
            EmailSubject = "Custom Subj",
            EmailTextTemplate = "Link={0}; Expires={1}",
            EmailHtmlTemplate = "<html>{0} {1}</html>"
        });

        await fixture.Service.RequestLinkAsync(_user.Email, new Uri("https://example.com/"));

        using (Assert.EnterMultipleScope())
        {
            var message = fixture.EmailSender.Messages.Single();
            Assert.That(message.Subject, Is.EqualTo("Custom Subj"));
            Assert.That(message.TextBody, Does.StartWith("Link=https://example.com/"));
            Assert.That(message.TextBody, Does.Contain("Expires=10"));
            Assert.That(message.HtmlBody, Is.Not.Null);
            Assert.That(message.HtmlBody, Does.Contain("https://example.com/"));
        }
    }

    [Test]
    public void MagicLinkAssertionValidatesToken()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => _ = new MagicLinkAssertion(" "));
            Assert.That(new MagicLinkAssertion("token", AuthenticationProviderKey.MagicLink).Token, Is.EqualTo("token"));
        }
    }

    [Test]
    public void RequestLinkValidatesArguments()
    {
        var fixture = CreateFixture(_user);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestLinkAsync(" ", new Uri("https://example.com/")));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.RequestLinkAsync(_user.Email, null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.VerifyLinkAsync(_user.Email, " "));
        }
    }

    [Test]
    public async Task ConstructLinkHandlesComplexExistingQueryStrings()
    {
        var fixture = CreateFixture(_user);
        var callbackUri = new Uri("https://example.com/signin?existing=val&email=old&token=old&"); // Trailing ampersand and duplicate params

        await fixture.Service.RequestLinkAsync(_user.Email, callbackUri);

        var message = fixture.EmailSender.Messages.Single();
        var link = ExtractLink(GetTextBody(message));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(link, Does.Contain("existing=val"));
            Assert.That(link, Does.Not.Contain("&&")); // Verify fix for double ampersands
            Assert.That(link, Does.Contain("email=USER%40EXAMPLE.COM"));
            Assert.That(link, Does.Not.Contain("email=old")); // Verify deduplication
            Assert.That(link, Does.Not.Contain("token=old")); // Verify deduplication
        }
    }

    [Test]
    public void ServiceConstructorRequiresDependencies()
    {
        var repository = new InMemoryIdentityRepository(_user);
        var identity = Mock.Of<IIdentityService>();
        var emailSender = new RecordingEmailSender();
        var rateLimiter = new StubRateLimiter(true, true, TimeProvider.System);
        var provider = new MagicLinkAuthenticationProvider(new Sha256TokenHasher());
        var tokenGenerator = new SecureTokenGenerator();
        var audit = new RecordingSecurityEventSink();
        var protector = Mock.Of<ISecretProtector>();
        var dependencies = new MagicLinkSignInDependencies(identity, repository, emailSender, rateLimiter, tokenGenerator, provider, audit, protector, TimeProvider.System);

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrow(() => _ = new MagicLinkSignInService(dependencies));
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInService(null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ProviderValidatesArguments()
    {
        var provider = new MagicLinkAuthenticationProvider(new Sha256TokenHasher());
        var repository = new InMemoryIdentityRepository(_user);

        using (Assert.EnterMultipleScope())
        {
            // AuthenticateAsync
            Assert.ThrowsAsync<ArgumentNullException>(() => provider.AuthenticateAsync(null!, null));

            // GetProviderKey
            Assert.Throws<ArgumentNullException>(() => provider.GetProviderKey(null!, Guid.Empty));

            // FindUserAsync
            Assert.ThrowsAsync<ArgumentNullException>(() => provider.FindUserAsync(null!, new AuthenticationContext(), repository));
            Assert.ThrowsAsync<ArgumentNullException>(() => provider.FindUserAsync(new MagicLinkAssertion("123"), null!, repository));
            Assert.ThrowsAsync<ArgumentNullException>(() => provider.FindUserAsync(new MagicLinkAssertion("123"), new AuthenticationContext(), null!));
        }
    }

    [Test]
    public void AddAshlarMagicLinkSignInResolvesServiceAndProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IIdentityRepository>(new InMemoryIdentityRepository(_user));
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton<IEmailSender, RecordingEmailSender>();
        services.AddAshlarMagicLinkSignIn(options => options.LinkLifetime = TimeSpan.FromHours(1));

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            var options = scope.ServiceProvider.GetRequiredService<IOptions<MagicLinkSignInOptions>>();
            Assert.That(options.Value.LinkLifetime, Is.EqualTo(TimeSpan.FromHours(1)));
            Assert.That(scope.ServiceProvider.GetRequiredService<IMagicLinkSignInService>(), Is.TypeOf<MagicLinkSignInService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IEnumerable<IAuthenticationProvider>>().Any(p => p.Key == AuthenticationProviderKey.MagicLink), Is.True);
        }
    }

    [Test]
    public void ProviderExposesMetadata()
    {
        var provider = new MagicLinkAuthenticationProvider(new Sha256TokenHasher());
        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.TypicalCredentialLength, Is.EqualTo(64));
            Assert.That(provider.ProtectsCredentials, Is.True);
            Assert.That(provider.PrepareCredentialValue(new MagicLinkAssertion("123"), null), Is.Null);
        }
    }

    private static Fixture CreateFixture(User? user = null, bool requestAllowed = true, bool verifyAllowed = true, MagicLinkSignInOptions? options = null, ISecretProtector? secretProtector = null)
    {
        var repository = new InMemoryIdentityRepository(user);
        var audit = new RecordingSecurityEventSink();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 3, 12, 0, 0, TimeSpan.Zero));
        var emailSender = new RecordingEmailSender();
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        var registry = new AuthenticationProviderRegistry([provider]);
        var protector = secretProtector ?? Mock.Of<ISecretProtector>();
        var credentialService = new CredentialService(repository, protector, timeProvider: time, securityEventSink: audit);
        var pipeline = new AuthenticationPipeline(registry, credentialService, audit, time);
        var identity = new IdentityService(repository, registry, credentialService, pipeline, audit, time);
        var rateLimiter = new StubRateLimiter(requestAllowed, verifyAllowed, time);
        var tokenGenerator = new SecureTokenGenerator();
        var dependencies = new MagicLinkSignInDependencies(identity, repository, emailSender, rateLimiter, tokenGenerator, provider, audit, protector, time);
        var service = new MagicLinkSignInService(dependencies, Options.Create(options ?? new MagicLinkSignInOptions()));
        return new Fixture(service, repository, emailSender, audit, time, tokenHasher);
    }

    private static string ExtractLink(string body)
    {
        var lines = body.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return lines.FirstOrDefault(l => l.StartsWith("https://", StringComparison.Ordinal)) ?? "";
    }

    private static string ExtractToken(string link)
    {
        var uri = new Uri(link);
        var query = uri.Query.TrimStart('?');
        var parts = query.Split('&');
        foreach (var part in parts)
        {
            var kvp = part.Split('=');
            if (kvp is ["token", _])
            {
                return Uri.UnescapeDataString(kvp[1]);
            }
        }
        return "";
    }

    private static string GetTextBody(EmailMessage message)
    {
        Assert.That(message.TextBody, Is.Not.Null);
        return message.TextBody ?? throw new AssertionException("Expected the email message to include a text body.");
    }

    private static string AllAuditText(Fixture fixture)
    {
        return string.Join("|", fixture.Audit.Events.SelectMany(e => new[] { e.EventType, e.FailureReason }.Concat(e.Properties?.Values ?? [])));
    }

    private sealed record Fixture(MagicLinkSignInService Service, InMemoryIdentityRepository Repository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time, ISecureTokenHasher TokenHasher);

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed, TimeProvider timeProvider) : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
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
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
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
    }
}
