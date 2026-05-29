using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Email;

internal sealed class EmailCodeSignInTests
{
    private readonly User _user = new() { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), Email = "user@example.com", IsActive = true };
    private static readonly string[] RequiredMfaFactors = ["totp"];

    [Test]
    public async Task RequestCodeSendsEmailAndStoresHashedCredentialForActiveUser()
    {
        var fixture = CreateFixture(_user);

        await fixture.Service.RequestCodeAsync(" User@Example.com ", new AuthenticationContext(IpAddress: "127.0.0.1", CorrelationId: "corr"));

        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.Repository.Credentials.Single();
        var code = ExtractCode(GetTextBody(message));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("USER@EXAMPLE.COM"));
            Assert.That(credential.ProviderType, Is.EqualTo(ProviderType.EmailCode));
            Assert.That(credential.ProviderName, Is.EqualTo(ProviderType.EmailCode.Value));
            Assert.That(credential.ProviderKey, Is.EqualTo(_user.Id.ToString("D")));
            Assert.That(credential.Purpose, Is.EqualTo("email-sign-in"));
            Assert.That(credential.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(credential.CredentialValue, Is.Not.EqualTo(code));
            Assert.That(credential.CredentialValue, Does.Not.Contain(code));
            Assert.That(credential.ExpiresAt, Is.EqualTo(fixture.Time.GetUtcNow().AddMinutes(10)));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.EmailCodeRequested), Is.True);
            Assert.That(AllAuditText(fixture), Does.Not.Contain(code));
            Assert.That(AllAuditText(fixture), Does.Not.Contain("USER@EXAMPLE.COM"));
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task RequestCodeDoesNotRevealOrSendForMissingUser()
    {
        var fixture = CreateFixture();

        await fixture.Service.RequestCodeAsync("missing@example.com");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.EmailCodeRequestSuppressed));
            Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo("user_missing"));
        }
    }

    [Test]
    public async Task RequestCodeDoesNotSendForInactiveUser()
    {
        var user = new User { Id = Guid.NewGuid(), Email = "inactive@example.com", IsActive = false };
        var fixture = CreateFixture(user);

        await fixture.Service.RequestCodeAsync(user.Email);

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

        await fixture.Service.RequestCodeAsync(_user.Email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.EmailCodeRequestRateLimited));
        }
    }

    [Test]
    public async Task VerifyCodeSucceedsAndConsumesCredential()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestCodeAsync(_user.Email);
        var code = ExtractCode(GetTextBody(fixture.EmailSender.Messages.Single()));

        var response = await fixture.Service.VerifyCodeAsync(_user.Email, code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(response.User?.Id, Is.EqualTo(_user.Id));
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.AuthenticationSucceeded), Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.CredentialConsumed), Is.True);
        }
    }

    [Test]
    public async Task VerifyCodeReturnsMfaRequiredWhenPolicyRequiresMfa()
    {
        var fixture = CreateFixture(_user, requireMfa: true);
        await fixture.Service.RequestCodeAsync(_user.Email);
        var code = ExtractCode(GetTextBody(fixture.EmailSender.Messages.Single()));

        var response = await fixture.Service.VerifyCodeAsync(_user.Email, code);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(response.User?.Id, Is.EqualTo(_user.Id));
            Assert.That(response.HandshakeToken, Is.EqualTo("mfa-token"));
            Assert.That(response.RequiredFactors, Is.EquivalentTo(RequiredMfaFactors));
        }
    }

    [Test]
    public async Task VerifyCodeUsesOrchestratorInsteadOfIdentityService()
    {
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        orchestrator
            .Setup(o => o.AuthenticateAsync(
                It.Is<AuthenticationContext>(context => string.Equals(context.Email, _user.Email, StringComparison.OrdinalIgnoreCase)),
                It.IsAny<EmailCodeAssertion>(),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, _user));
        var identity = new Mock<IIdentityService>(MockBehavior.Strict);
        var fixture = CreateFixture(_user, authenticationOrchestrator: orchestrator.Object, identityService: identity.Object);

        var response = await fixture.Service.VerifyCodeAsync(_user.Email, "123456");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            orchestrator.Verify(o => o.AuthenticateAsync(
                It.Is<AuthenticationContext>(context => string.Equals(context.Email, _user.Email, StringComparison.OrdinalIgnoreCase)),
                It.IsAny<EmailCodeAssertion>(),
                null,
                It.IsAny<CancellationToken>()), Times.Once);
            identity.Verify(i => i.LoginAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task VerifyCodeFailsForWrongCode()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestCodeAsync(_user.Email);

        var response = await fixture.Service.VerifyCodeAsync(_user.Email, "000000");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.AuthenticationFailed), Is.True);
        }
    }

    [Test]
    public async Task VerifyCodeFailsForExpiredCredential()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestCodeAsync(_user.Email);
        var code = ExtractCode(GetTextBody(fixture.EmailSender.Messages.Single()));
        fixture.Time.Advance(TimeSpan.FromMinutes(11));

        var response = await fixture.Service.VerifyCodeAsync(_user.Email, code);

        Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
    }

    [Test]
    public async Task VerifyRateLimitBlocksVerification()
    {
        var orchestrator = new Mock<IAuthenticationOrchestrator>(MockBehavior.Strict);
        var fixture = CreateFixture(_user, verifyAllowed: false, authenticationOrchestrator: orchestrator.Object);

        var response = await fixture.Service.VerifyCodeAsync(_user.Email, "123456");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.RateLimited));
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.EmailCodeVerificationRateLimited));
            orchestrator.Verify(o => o.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                null,
                It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public void ProviderRejectsWrongAssertionTypeAndUsesExpectedIdentity()
    {
        var provider = CreateProvider();
        var assertion = new LocalPasswordAssertion("pw");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.Key, Is.EqualTo(AuthenticationProviderKey.EmailCode));
            Assert.ThrowsAsync<ArgumentException>(() => provider.AuthenticateAsync(assertion, null));
        }
    }

    [Test]
    public void ProviderConstructorRequiresHasherSelector()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeAuthenticationProvider(null!));
    }

    [Test]
    public async Task ProviderFindUserReturnsNullForWrongAssertionOrMissingEmail()
    {
        var provider = CreateProvider();
        var repository = new InMemoryUserCredentialStore(_user);

        var wrongAssertion = await provider.FindUserAsync(new LocalPasswordAssertion("pw"), new AuthenticationContext(_user.Email), repository);
        var missingEmail = await provider.FindUserAsync(new EmailCodeAssertion("123456"), new AuthenticationContext(" "), repository);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongAssertion, Is.Null);
            Assert.That(missingEmail, Is.Null);
        }
    }

    [Test]
    public async Task ProviderFailsMalformedOrWrongPurposeCredential()
    {
        var provider = CreateProvider();
        var assertion = new EmailCodeAssertion("123456");
        var malformed = CreateCredential("not-base64", "email-sign-in");
        var wrongPurpose = CreateCredential(Convert.ToBase64String([0x7f, 1]), "other");
        var missingValue = CreateCredential(null, "email-sign-in");

        var malformedResult = await provider.AuthenticateAsync(assertion, malformed);
        var wrongPurposeResult = await provider.AuthenticateAsync(assertion, wrongPurpose);
        var missingValueResult = await provider.AuthenticateAsync(assertion, missingValue);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(malformedResult.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
            Assert.That(wrongPurposeResult.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
            Assert.That(missingValueResult.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
        }
    }

    [Test]
    public async Task EmailSubjectAndBodyOptionsAreApplied()
    {
        var fixture = CreateFixture(_user, options: new EmailCodeSignInOptions
        {
            CodeLength = 4,
            EmailSubject = "Custom",
            EmailTextTemplate = "Code={0}; Minutes={1}"
        });

        await fixture.Service.RequestCodeAsync(_user.Email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages.Single().Subject, Is.EqualTo("Custom"));
            Assert.That(fixture.EmailSender.Messages.Single().TextBody, Does.Match(@"^Code=\d{4}; Minutes=10$"));
        }
    }

    [Test]
    public async Task CreateOrReplaceCredentialReplacesExistingEmailCredential()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestCodeAsync(_user.Email);
        var firstId = fixture.Repository.Credentials.Single().Id;

        await fixture.Service.RequestCodeAsync(_user.Email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.Repository.Credentials.Single().Id, Is.Not.EqualTo(firstId));
            Assert.That(fixture.EmailSender.Messages, Has.Count.EqualTo(2));
        }
    }

    [Test]
    public void EmailCodeAssertionValidatesCode()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => _ = new EmailCodeAssertion(" "));
            Assert.That(new EmailCodeAssertion("123456", AuthenticationProviderKey.EmailCode).Code, Is.EqualTo("123456"));
        }
    }

    [Test]
    public void RequestCodeValidatesEmailAndCodeLength()
    {
        var fixture = CreateFixture(_user, options: new EmailCodeSignInOptions { CodeLength = 0 });

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestCodeAsync(" "));
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Service.RequestCodeAsync(_user.Email));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.VerifyCodeAsync(_user.Email, " "));
        }
    }

    [Test]
    public void RequestCodeRejectsTooLongCodeLength()
    {
        var fixture = CreateFixture(_user, options: new EmailCodeSignInOptions { CodeLength = 10 });

        Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => fixture.Service.RequestCodeAsync(_user.Email));
    }

    [Test]
    public void EmailCodeOptionsValidateSupportedValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions()), Is.True);
            Assert.That(EmailCodeSignInOptions.Validate(null), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { CodeLength = 0 }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { CodeLength = 10 }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { CodeLifetime = TimeSpan.Zero }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { RequestRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) } }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { VerificationRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) } }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { RequestRateLimit = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero } }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { VerificationRateLimit = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero } }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { EmailSubject = " " }), Is.False);
            Assert.That(EmailCodeSignInOptions.Validate(new EmailCodeSignInOptions { EmailTextTemplate = " " }), Is.False);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ServiceConstructorRequiresDependenciesAndDependencyBundleValidatesRequiredServices()
    {
        var repository = new InMemoryUserCredentialStore(_user);
        var identity = Mock.Of<IIdentityService>();
        var emailSender = new RecordingEmailSender();
        var rateLimiter = new StubRateLimiter(true, true, TimeProvider.System);
        var provider = CreateProvider();
        var core = new IdentityContext(repository, repository, identity, new NullTransactionProvider());
        var dependencies = new EmailCodeSignInDependencies(core, emailSender, rateLimiter, provider, Mock.Of<IAuthenticationOrchestrator>(), TimeProvider.System);

        using (Assert.EnterMultipleScope())
        {
            Assert.DoesNotThrow(() => _ = new EmailCodeSignInService(dependencies));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInService(null!));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInDependencies(null!, emailSender, rateLimiter, provider, Mock.Of<IAuthenticationOrchestrator>(), TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInDependencies(core, null!, rateLimiter, provider, Mock.Of<IAuthenticationOrchestrator>(), TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInDependencies(core, emailSender, null!, provider, Mock.Of<IAuthenticationOrchestrator>(), TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInDependencies(core, emailSender, rateLimiter, null!, Mock.Of<IAuthenticationOrchestrator>(), TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInDependencies(core, emailSender, rateLimiter, provider, null!, TimeProvider.System));
            Assert.Throws<ArgumentNullException>(() => _ = new EmailCodeSignInDependencies(core, emailSender, rateLimiter, provider, Mock.Of<IAuthenticationOrchestrator>(), null!));
        }
    }

    [Test]
    public void AddAshlarEmailCodeSignInResolvesServiceAndProvider()
    {
        var services = new ServiceCollection();
        var repository = new InMemoryUserCredentialStore(_user);
        services.AddSingleton<IUserRepository>(repository);
        services.AddSingleton<ICredentialRepository>(repository);
        services.AddSingleton(Mock.Of<IAuthenticationHandshakeRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton<IEmailSender, RecordingEmailSender>();
        services.AddAshlarEmailCodeSignIn(options => options.CodeLength = 6);

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IEmailCodeSignInService>(), Is.TypeOf<EmailCodeSignInService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IEnumerable<IAuthenticationProvider>>().Any(p => p.Key == AuthenticationProviderKey.EmailCode), Is.True);
        }
    }

    [Test]
    public void AddAshlarEmailCodeSignInRegistersOptionsValidation()
    {
        var services = new ServiceCollection();
        services.AddAshlarEmailCodeSignIn(options => options.CodeLength = EmailCodeSignInOptions.MaximumCodeLength + 1);

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<EmailCodeSignInOptions>>();

        Assert.Throws<OptionsValidationException>(() => _ = options.Value);
    }

    private static Fixture CreateFixture(
        User? user = null,
        bool requestAllowed = true,
        bool verifyAllowed = true,
        EmailCodeSignInOptions? options = null,
        bool requireMfa = false,
        IAuthenticationOrchestrator? authenticationOrchestrator = null,
        IIdentityService? identityService = null)
    {
        var repository = new InMemoryUserCredentialStore(user);
        var audit = new RecordingSecurityEventSink();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 3, 12, 0, 0, TimeSpan.Zero));
        var emailSender = new RecordingEmailSender();
        var provider = CreateProvider();
        var registry = new AuthenticationProviderRegistry([provider]);
        var credentialService = new CredentialService(
            repository,
            repository,
            Mock.Of<ISecretProtector>(),
            new NullTransactionProvider(),
            new CredentialServiceDependencies(TimeProvider: time, SecurityEventSink: audit));
        var pipeline = new AuthenticationPipeline(
            registry,
            credentialService,
            new NullTransactionProvider(),
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(audit, time));
        var identity = identityService ?? new IdentityService(
            repository,
            registry,
            credentialService,
            pipeline,
            new NullTransactionProvider(),
            new IdentityServiceDependencies(audit, time));
        var orchestrator = authenticationOrchestrator ?? CreateOrchestrator(pipeline, user, requireMfa);
        var rateLimiter = new StubRateLimiter(requestAllowed, verifyAllowed, time);
        var core = new IdentityContext(repository, repository, identity, new NullTransactionProvider());
        var dependencies = new EmailCodeSignInDependencies(core, emailSender, rateLimiter, provider, orchestrator, time, audit);
        var service = new EmailCodeSignInService(dependencies, Options.Create(options ?? new EmailCodeSignInOptions()));
        return new Fixture(service, repository, emailSender, audit, time);
    }

    private static AuthenticationOrchestrator CreateOrchestrator(IAuthenticationPipeline pipeline, User? user, bool requireMfa)
    {
        var policy = new StaticMfaPolicyEvaluator(requireMfa);
        var handshakes = new Mock<IAuthenticationHandshakeService>();
        if (requireMfa && user != null)
        {
            handshakes
                .Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((CreateAuthenticationHandshakeRequest request, CancellationToken _) =>
                {
                    var handshake = new AuthenticationHandshake(
                        Guid.NewGuid(),
                        user.Id,
                        "hash",
                        DateTimeOffset.UtcNow,
                        DateTimeOffset.UtcNow.AddMinutes(5),
                        false,
                        false,
                        request.RequiredFactors.ToHashSet(StringComparer.OrdinalIgnoreCase),
                        new HashSet<string>());
                    return Result.Success(new AuthenticationHandshakeCreated(handshake, "mfa-token"));
                });
        }

        return new AuthenticationOrchestrator(pipeline, Mock.Of<IAuthenticationFactorPipeline>(), handshakes.Object, policy, Mock.Of<IAuthenticationProviderRegistry>());
    }

    private static EmailCodeAuthenticationProvider CreateProvider()
    {
        return new EmailCodeAuthenticationProvider(new PasswordHasherSelector([new TestPasswordHasher()]));
    }

    private static UserCredential CreateCredential(string? credentialValue, string purpose)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ProviderType = ProviderType.EmailCode,
            ProviderName = ProviderType.EmailCode.Value,
            ProviderKey = Guid.NewGuid().ToString("D"),
            Version = "v1",
            CredentialValue = credentialValue,
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Purpose = purpose
        };
    }

    private static string ExtractCode(string body)
    {
        return new string(body.Where(char.IsDigit).Take(6).ToArray());
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

    private sealed record Fixture(EmailCodeSignInService Service, InMemoryUserCredentialStore Repository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time);

    private sealed class TestPasswordHasher : IPasswordHasher
    {
        public byte Version => 0x7f;

        public byte[] HashPassword(ReadOnlySpan<char> password)
        {
            return [Version, .. System.Text.Encoding.UTF8.GetBytes(password.ToString())];
        }

        public bool VerifyPassword(ReadOnlySpan<char> password, ReadOnlySpan<byte> encodedHash)
        {
            return encodedHash.Length > 1 && encodedHash[0] == Version && System.Text.Encoding.UTF8.GetString(encodedHash[1..]) == password.ToString();
        }
    }

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed, TimeProvider timeProvider) : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            var allowed = attempt.Purpose == "email-code-request" ? requestAllowed : verifyAllowed;
            return Task.FromResult(new RateLimitDecision
            {
                Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
                Remaining = allowed ? 1 : 0,
                WindowResetAt = timeProvider.GetUtcNow().Add(rule.Window)
            });
        }
    }

    private sealed class StaticMfaPolicyEvaluator(bool requireMfa) : IMfaPolicyEvaluator
    {
        public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            var evaluation = requireMfa
                ? new MfaPolicyEvaluation(true, new MfaRequirement(RequiredMfaFactors))
                : new MfaPolicyEvaluation(false);
            return Task.FromResult(evaluation);
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

    private sealed class InMemoryUserCredentialStore(params User?[] users) : IUserRepository, ICredentialRepository
    {
        private readonly List<User> _users = users.OfType<User>().ToList();
        public List<UserCredential> Credentials { get; } = [];

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(_users.SingleOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)));
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(_users.SingleOrDefault(u => u.Id == userId));
        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default) => Task.FromResult(Credentials.SingleOrDefault(c => c.UserId == userId && c.ProviderType == type && string.Equals(c.ProviderName, providerName, StringComparison.OrdinalIgnoreCase) && (providerKey == null || c.ProviderKey == providerKey))?.Clone());
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
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
