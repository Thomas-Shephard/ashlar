using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting;
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
    private readonly User _user = new() { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), DisplayEmail = "user@example.com", AccountState = UserAccountState.Active };

    [Test]
    public async Task RequestLinkSendsEmailAndStoresHashedCredentialForActiveUser()
    {
        var user = new User { Id = _user.Id, DisplayEmail = "Stored.User@Example.COM", AccountState = _user.AccountState };
        var fixture = CreateFixture(user);
        var baseUri = new Uri("https://myapp.com/verify");

        await fixture.Service.RequestLinkAsync(" stored.user@example.com ", baseUri, new AuthenticationContext(IpAddress: "127.0.0.1", CorrelationId: "corr"));

        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.Repository.Credentials.Single();

        Assert.That(message.TextBody, Is.Not.Null);
        var token = ExtractToken(message.TextBody);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(message.To, Is.EqualTo("Stored.User@Example.COM"));
            Assert.That(credential.ProviderType, Is.EqualTo(ProviderType.MagicLink));
            Assert.That(credential.ProviderName, Is.EqualTo(ProviderType.MagicLink.Value));
            Assert.That(credential.ProviderKey, Is.EqualTo(fixture.TokenHasher.HashToken(token)));
            Assert.That(credential.Purpose, Is.EqualTo("magic-link-sign-in"));
            Assert.That(credential.Status, Is.EqualTo(CredentialStatus.Active));
            Assert.That(credential.ExpiresAt, Is.EqualTo(fixture.Time.GetUtcNow().AddMinutes(10)));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.MagicLinkRequested), Is.True);
            Assert.That(message.TextBody, Does.Contain($"token={token}"));
            Assert.That(message.TextBody, Does.Not.Contain("STORED.USER@EXAMPLE.COM"));
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
            var requestAttempts = fixture.RateLimiter.Attempts.Where(a => a.Purpose == "magic-link-request").ToArray();
            Assert.That(requestAttempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-request", "source", "source:ip:127.0.0.1")));
            Assert.That(requestAttempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-request", "email", "email:STORED.USER@EXAMPLE.COM")));
        }
    }

    [Test]
    public async Task RequestLinkEnqueuesTransactionalOutboxBeforeCommit()
    {
        var fixture = CreateFixture(_user, transactionalEmailSender: true);

        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));

        Assert.That(fixture.Events, Is.EqualTo(SendBeforeCommitEvents));
    }

    [Test]
    public async Task RequestLinkSendsNonTransactionalEmailAfterCommit()
    {
        var fixture = CreateFixture(_user);

        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));

        Assert.That(fixture.Events, Is.EqualTo(CommitBeforeSendEvents));
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

        var ex = Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://evil.example/verify")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ex?.ParamName, Is.EqualTo("uri"));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
        }
    }

    [TestCase(UserAccountState.Disabled, "user_disabled")]
    [TestCase(UserAccountState.Locked, "user_locked")]
    [TestCase(UserAccountState.Suspended, "user_suspended")]
    public async Task RequestLinkDoesNotSendForUnavailableUser(UserAccountState accountState, string failureReason)
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "inactive@example.com", AccountState = accountState };
        var fixture = CreateFixture(user);

        await fixture.Service.RequestLinkAsync(user.DisplayEmail, new Uri("https://myapp.com/verify"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo(failureReason));
        }
    }

    [Test]
    public async Task RequestLinkUsesGenericSuppressionReasonForUnknownUnavailableState()
    {
        var user = new User { Id = Guid.NewGuid(), DisplayEmail = "inactive@example.com", AccountState = (UserAccountState)999 };
        var fixture = CreateFixture(user);

        await fixture.Service.RequestLinkAsync(user.DisplayEmail, new Uri("https://myapp.com/verify"));

        Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo("invalid_credentials"));
    }

    [Test]
    public async Task RequestSourceRateLimitBlocksBeforeEmailLimitAndIssuance()
    {
        var fixture = CreateFixture(_user, requestAllowed: false);

        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"), new AuthenticationContext(IpAddress: "203.0.113.10"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Repository.GetUserByEmailCalls, Is.Zero);
            Assert.That(fixture.RateLimiter.Attempts.Select(a => a.Key), Is.EqualTo(new[] { ExpectedRateLimitKey("magic-link-request", "source", "source:ip:203.0.113.10") }));
            var auditEvent = fixture.Audit.Events.Single();
            Assert.That(auditEvent.EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkRequestRateLimited));
            Assert.That(auditEvent.FailureReason, Is.EqualTo("rate_limited"));
            Assert.That(AllAuditText(fixture), Does.Not.Contain(_user.DisplayEmail));
            Assert.That(AllAuditText(fixture), Does.Not.Contain("https://myapp.com/verify"));
        }
    }

    [Test]
    public async Task RequestEmailRateLimitBlocksAfterSourcePasses()
    {
        var fixture = CreateFixture(_user);
        fixture.RateLimiter.BlockedKeys.Add(ExpectedRateLimitKey("magic-link-request", "email", "email:USER@EXAMPLE.COM"));

        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"), new AuthenticationContext(IpAddress: "203.0.113.10"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Repository.Credentials, Is.Empty);
            Assert.That(fixture.Repository.GetUserByEmailCalls, Is.Zero);
            Assert.That(fixture.RateLimiter.Attempts.Select(a => a.Key), Is.EqualTo(new[]
            {
                ExpectedRateLimitKey("magic-link-request", "source", "source:ip:203.0.113.10"),
                ExpectedRateLimitKey("magic-link-request", "email", "email:USER@EXAMPLE.COM")
            }));
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkRequestRateLimited));
        }
    }

    [Test]
    public async Task VerifyLinkSucceedsAndConsumesCredential()
    {
        var fixture = CreateFixture(_user);
        var baseUri = new Uri("https://myapp.com/verify?existing=val");
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, baseUri);

        var message = fixture.EmailSender.Messages.Single();
        Assert.That(message.TextBody, Is.Not.Null);
        var token = ExtractToken(message.TextBody);

        var response = await fixture.Service.VerifyLinkAsync(token);

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
    public async Task VerifyLinkReturnsMfaRequiredWhenPolicyRequiresMfa()
    {
        var fixture = CreateFixture(_user, requireMfa: true);
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));
        var token = ExtractToken(fixture.EmailSender.Messages.Single().TextBody);

        var response = await fixture.Service.VerifyLinkAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(response.User?.Id, Is.EqualTo(_user.Id));
            Assert.That(response.HandshakeToken, Is.EqualTo("mfa-token"));
            Assert.That(response.RequiredFactors, Is.EquivalentTo(RequiredMfaFactors));
        }
    }

    [Test]
    public async Task VerifyLinkUsesOrchestratorInsteadOfIdentityService()
    {
        var orchestrator = new Mock<IAuthenticationOrchestrator>();
        orchestrator
            .Setup(o => o.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<MagicLinkAssertion>(),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, _user));
        var identity = new Mock<IIdentityService>(MockBehavior.Strict);
        var fixture = CreateFixture(_user, authenticationOrchestrator: orchestrator.Object, identityService: identity.Object);

        var response = await fixture.Service.VerifyLinkAsync("token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            orchestrator.Verify(o => o.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<MagicLinkAssertion>(),
                null,
                It.IsAny<CancellationToken>()), Times.Once);
            identity.Verify(i => i.LoginAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task RequestLinkRevokesPreviousLinks()
    {
        var fixture = CreateFixture(_user);
        var baseUri = new Uri("https://myapp.com/verify");

        // Request first link
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, baseUri);
        var firstToken = ExtractToken(fixture.EmailSender.Messages[0].TextBody);

        // Request second link
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, baseUri);
        var secondToken = ExtractToken(fixture.EmailSender.Messages[1].TextBody);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(2));
            Assert.That(fixture.Repository.Credentials.Count(c => c.Status == CredentialStatus.Revoked), Is.EqualTo(1));
            Assert.That(fixture.Repository.Credentials.Single(c => c.Status == CredentialStatus.Active).ProviderKey, Is.EqualTo(fixture.TokenHasher.HashToken(secondToken)));

            // First token should fail (already revoked)
            var response1 = await fixture.Service.VerifyLinkAsync(firstToken);
            Assert.That(response1.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));

            // Second token should succeed
            var response2 = await fixture.Service.VerifyLinkAsync(secondToken);
            Assert.That(response2.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
        }
    }

    [Test]
    public async Task VerifyLinkFailsForWrongToken()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));

        var response = await fixture.Service.VerifyLinkAsync("wrong-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.AuthenticationFailed), Is.True);
        }
    }

    [Test]
    public async Task VerifyLinkFailsGenericallyWhenTokenResolvesUserFromDifferentTenant()
    {
        var tenantId = Guid.NewGuid();
        var otherTenantId = Guid.NewGuid();
        var user = new User { Id = _user.Id, DisplayEmail = _user.DisplayEmail, AccountState = _user.AccountState, TenantId = tenantId };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestLinkAsync(user.DisplayEmail, new Uri("https://myapp.com/verify"), new AuthenticationContext(TenantId: tenantId));
        var token = ExtractToken(fixture.EmailSender.Messages.Single().TextBody);

        var response = await fixture.Service.VerifyLinkAsync(token, new AuthenticationContext(TenantId: otherTenantId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(response.User, Is.Null);
            Assert.That(response.ErrorMessage, Is.EqualTo("Authentication failed."));
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.Audit.Events.Any(e =>
                e.EventType == AshlarSecurityEventTypes.AuthenticationFailed &&
                e.FailureReason == SecurityEventFailureReasons.InvalidCredentials &&
                e.UserId == null), Is.True);
        }
    }

    [Test]
    public async Task VerifyLinkFailsGenericallyWhenTenantUserTokenHasNoTenantContext()
    {
        var tenantId = Guid.NewGuid();
        var user = new User { Id = _user.Id, DisplayEmail = _user.DisplayEmail, AccountState = _user.AccountState, TenantId = tenantId };
        var fixture = CreateFixture(user);
        await fixture.Service.RequestLinkAsync(user.DisplayEmail, new Uri("https://myapp.com/verify"), new AuthenticationContext(TenantId: tenantId));
        var token = ExtractToken(fixture.EmailSender.Messages.Single().TextBody);

        var response = await fixture.Service.VerifyLinkAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(response.User, Is.Null);
            Assert.That(response.ErrorMessage, Is.EqualTo("Authentication failed."));
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
        }
    }

    [Test]
    public async Task VerifyLinkSucceedsWhenTenantUserTokenHasMatchingTenantContext()
    {
        var tenantId = Guid.NewGuid();
        var user = new User { Id = _user.Id, DisplayEmail = _user.DisplayEmail, AccountState = _user.AccountState, TenantId = tenantId };
        var fixture = CreateFixture(user);
        var context = new AuthenticationContext(TenantId: tenantId);
        await fixture.Service.RequestLinkAsync(user.DisplayEmail, new Uri("https://myapp.com/verify"), context);
        var token = ExtractToken(fixture.EmailSender.Messages.Single().TextBody);

        var response = await fixture.Service.VerifyLinkAsync(token, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(response.User?.Id, Is.EqualTo(user.Id));
        }
    }

    [Test]
    public async Task VerifyLinkFailsForOverlongTokenAfterSourceRateLimitCheck()
    {
        var fixture = CreateFixture(_user);
        var token = new string('a', 257);

        var response = await fixture.Service.VerifyLinkAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(fixture.RateLimiter.Attempts.Single().Purpose, Is.EqualTo("magic-link-verify"));
            Assert.That(fixture.RateLimiter.Attempts.Single().Key, Is.EqualTo(ExpectedRateLimitKey("magic-link-verify", "source", "source:anonymous")));
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationFailed));
        }
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task VerifyLinkFailsGenericallyForMissingTokenWithoutMutatingState(string? token)
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));
        fixture.Audit.Events.Clear();
        fixture.RateLimiter.Attempts.Clear();

        var response = await fixture.Service.VerifyLinkAsync(token!);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
            Assert.That(response.ErrorMessage, Is.EqualTo("Authentication failed."));
            Assert.That(fixture.Repository.Credentials, Has.Count.EqualTo(1));
            Assert.That(fixture.RateLimiter.Attempts.Single().Purpose, Is.EqualTo("magic-link-verify"));
            var auditEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.AuthenticationFailed);
            Assert.That(auditEvent.FailureReason, Is.EqualTo("invalid_token"));
        }
    }

    [Test]
    public async Task VerifyLinkFailsForExpiredCredential()
    {
        var fixture = CreateFixture(_user);
        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));

        var message = fixture.EmailSender.Messages.Single();
        Assert.That(message.TextBody, Is.Not.Null);
        var token = ExtractToken(message.TextBody);
        fixture.Time.Advance(TimeSpan.FromMinutes(11));

        var response = await fixture.Service.VerifyLinkAsync(token);

        Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Failed));
    }

    [Test]
    public async Task VerifyRateLimitBlocksVerification()
    {
        var orchestrator = new Mock<IAuthenticationOrchestrator>(MockBehavior.Strict);
        var fixture = CreateFixture(_user, verifyAllowed: false, authenticationOrchestrator: orchestrator.Object);

        var response = await fixture.Service.VerifyLinkAsync("any-token");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.RateLimited));
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited));
            orchestrator.Verify(o => o.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                null,
                It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task VerifyRateLimitBlocksVerificationWhenTokenBucketIsBlocked()
    {
        var orchestrator = new Mock<IAuthenticationOrchestrator>(MockBehavior.Strict);
        var fixture = CreateFixture(_user, authenticationOrchestrator: orchestrator.Object);
        var tokenHash = fixture.TokenHasher.HashToken("any-token");
        fixture.RateLimiter.BlockedKeys.Add(ExpectedRateLimitKey("magic-link-verify", "token-hash", $"token:{tokenHash}"));

        var response = await fixture.Service.VerifyLinkAsync("any-token", new AuthenticationContext(IpAddress: "203.0.113.90"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.RateLimited));
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.MagicLinkVerificationRateLimited));
            Assert.That(fixture.RateLimiter.Attempts.Count(a => a.Purpose == "magic-link-verify"), Is.EqualTo(2));
            orchestrator.Verify(o => o.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                null,
                It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    [Test]
    public async Task VerifyLinkWithoutIpUsesTokenScopedRateLimitKey()
    {
        var fixture = CreateFixture(_user);

        await fixture.Service.VerifyLinkAsync("attempt-token");

        var attempts = fixture.RateLimiter.Attempts.Where(a => a.Purpose == "magic-link-verify").ToArray();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(attempts, Has.Length.EqualTo(2));
            Assert.That(attempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-verify", "source", "source:anonymous")));
            Assert.That(attempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-verify", "token-hash", $"token:{fixture.TokenHasher.HashToken("attempt-token")}")));
        }
    }

    [Test]
    public async Task VerifyLinkWithIpUsesLayeredSourceAndTokenScopedRateLimitKeys()
    {
        var fixture = CreateFixture(_user);
        var context = new AuthenticationContext(IpAddress: "127.0.0.1", CorrelationId: "corr");

        await fixture.Service.VerifyLinkAsync("attempt-token", context);

        var attempts = fixture.RateLimiter.Attempts.Where(a => a.Purpose == "magic-link-verify").ToArray();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(attempts, Has.Length.EqualTo(2));
            Assert.That(attempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-verify", "source", "source:ip:127.0.0.1")));
            Assert.That(attempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-verify", "token-hash", $"token:{fixture.TokenHasher.HashToken("attempt-token")}")));
        }
    }

    [Test]
    public async Task VerifyLinkWithoutIpUsesAnonymousSourceAndTokenScopedRateLimitKeys()
    {
        var fixture = CreateFixture(_user);
        var context = new AuthenticationContext(CorrelationId: "corr");

        await fixture.Service.VerifyLinkAsync("attempt-token", context);

        var attempts = fixture.RateLimiter.Attempts.Where(a => a.Purpose == "magic-link-verify").ToArray();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(attempts, Has.Length.EqualTo(2));
            Assert.That(attempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-verify", "source", "source:anonymous")));
            Assert.That(attempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("magic-link-verify", "token-hash", $"token:{fixture.TokenHasher.HashToken("attempt-token")}")));
        }
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

            var user = await ((IAuthenticationUserResolver)provider).FindUserAsync(assertion, new AuthenticationContext(), new InMemoryUserCredentialStore());
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
    public async Task ProviderTreatsOverlongTokenAsUnlinked()
    {
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        var assertion = new MagicLinkAssertion(new string('a', 257));
        var repository = new InMemoryUserCredentialStore(_user);

        var providerKey = provider.GetProviderKey(assertion, _user.Id);
        var user = await ((IAuthenticationUserResolver)provider).FindUserAsync(assertion, new AuthenticationContext(), repository);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(providerKey, Is.Empty);
            Assert.That(user, Is.Null);
        }
    }

    [Test]
    public async Task EmailSubjectAndBodyOptionsAreApplied()
    {
        var fixture = CreateFixture(_user, options: new MagicLinkSignInOptions
        {
            EmailSubject = "Custom",
            EmailTextTemplate = "Link={0}"
        });

        await fixture.Service.RequestLinkAsync(_user.DisplayEmail, new Uri("https://myapp.com/verify"));

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
    public void MagicLinkAssertionIsNotPublicConsumerApi()
    {
        Assert.That(typeof(IMagicLinkSignInService).Assembly.GetExportedTypes(), Does.Not.Contain(typeof(MagicLinkAssertion)));
    }

    [Test]
    public void RequestLinkValidatesArguments()
    {
        var fixture = CreateFixture(_user);

        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.RequestLinkAsync(_user.DisplayEmail, null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RequestLinkAsync(" ", new Uri("https://myapp.com/verify")));
        }
    }

    [Test]
    public void ServiceConstructorRequiresDependencies()
    {
        var repository = new InMemoryUserCredentialStore(_user);
        var identity = Mock.Of<IIdentityService>();
        var emailSender = new RecordingEmailSender();
        var rateLimiter = new StubRateLimiter(true, true, TimeProvider.System);
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher());
        var uriValidator = Mock.Of<IUriValidator>();
        var provider = new MagicLinkAuthenticationProvider(tokenContext.Hasher);
        var core = new IdentityContext(repository, repository, identity, new NullTransactionProvider());
        var infrastructure = new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator);
        var audit = new IdentityAuditContext(TimeProvider.System, Mock.Of<ISecurityEventSink>());
        var dependencies = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, Mock.Of<IAuthenticationOrchestrator>(), audit);

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
        var repository = new InMemoryUserCredentialStore(_user);
        var identity = Mock.Of<IIdentityService>();
        var core = new IdentityContext(repository, repository, identity, new NullTransactionProvider());
        var tokenContext = new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher());
        var infrastructure = new IdentityInfrastructureContext(Mock.Of<IEmailSender>(), Mock.Of<IAuthenticationRateLimiter>(), Mock.Of<IUriValidator>());
        var provider = new MagicLinkAuthenticationProvider(tokenContext.Hasher);
        var audit = new IdentityAuditContext(TimeProvider.System, Mock.Of<ISecurityEventSink>());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(null!, tokenContext, infrastructure, provider, Mock.Of<IAuthenticationOrchestrator>(), audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, null!, infrastructure, provider, Mock.Of<IAuthenticationOrchestrator>(), audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, null!, provider, Mock.Of<IAuthenticationOrchestrator>(), audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, null!, Mock.Of<IAuthenticationOrchestrator>(), audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, null!, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, Mock.Of<IAuthenticationOrchestrator>(), null!));
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
        var repository = new InMemoryUserCredentialStore(_user);
        services.AddSingleton<IUserRepository>(repository);
        services.AddSingleton<ICredentialRepository>(repository);
        services.AddSingleton(Mock.Of<IAuthenticationHandshakeRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton<IEmailSender, RecordingEmailSender>();
        services.AddAshlarNullTransactions();
        services.AddAshlarMagicLinkSignIn(options => options.EmailSubject = "Modified");
        services.AddAshlarNoMfaPolicy();

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

    [Test]
    public void MagicLinkOptionsValidateSupportedValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions()), Is.True);
            Assert.That(MagicLinkSignInOptions.Validate(null), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { LinkLifetime = TimeSpan.Zero }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { RequestRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) } }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { VerificationRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) } }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { RequestRateLimit = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero } }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { VerificationRateLimit = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero } }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { EmailSubject = " " }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { EmailTextTemplate = " " }), Is.False);
            Assert.That(MagicLinkSignInOptions.Validate(new MagicLinkSignInOptions { LinkTokenParameterName = " " }), Is.False);
        }
    }

    [Test]
    public void AddAshlarMagicLinkSignInRegistersOptionsValidation()
    {
        var services = new ServiceCollection();
        services.AddAshlarMagicLinkSignIn(options => options.LinkTokenParameterName = " ");

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<MagicLinkSignInOptions>>();

        Assert.Throws<OptionsValidationException>(() => _ = options.Value);
    }

    private static readonly string[] SendBeforeCommitEvents = ["send", "commit"];
    private static readonly string[] CommitBeforeSendEvents = ["commit", "send"];
    private static readonly string[] RequiredMfaFactors = ["totp"];

    private static Fixture CreateFixture(
        User? user = null,
        bool requestAllowed = true,
        bool verifyAllowed = true,
        MagicLinkSignInOptions? options = null,
        bool callbackAllowed = true,
        bool transactionalEmailSender = false,
        bool requireMfa = false,
        IAuthenticationOrchestrator? authenticationOrchestrator = null,
        IIdentityService? identityService = null)
    {
        var repository = new InMemoryUserCredentialStore(user);
        var audit = new RecordingSecurityEventSink();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 3, 12, 0, 0, TimeSpan.Zero));
        var events = new List<string>();
        RecordingEmailSender emailSender = transactionalEmailSender ? new RecordingTransactionalEmailSender(events) : new RecordingEmailSender(events);
        var tokenHasher = new Sha256TokenHasher();
        var provider = new MagicLinkAuthenticationProvider(tokenHasher);
        var registry = new AuthenticationProviderRegistry([provider]);
        var transactionProvider = new RecordingTransactionProvider(events);
        var credentialService = new CredentialService(
            repository,
            repository,
            Mock.Of<ISecretProtector>(),
            transactionProvider,
            new CredentialServiceDependencies(TimeProvider: time, SecurityEventSink: audit));
        var pipeline = new AuthenticationPipeline(
            registry,
            credentialService,
            transactionProvider,
            AllowPrimaryAuthenticationRateLimiter.Instance,
            AllowAuthenticationFactorRateLimiter.Instance,
            new AuthenticationPipelineDependencies(audit, time));
        var identity = identityService ?? new IdentityService(
            repository,
            registry,
            pipeline);
        var orchestrator = authenticationOrchestrator ?? CreateOrchestrator(pipeline, user, requireMfa);
        var core = new IdentityContext(repository, repository, identity, transactionProvider);
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

        var dependencies = new MagicLinkSignInDependencies(core, tokenContext, infrastructure, provider, orchestrator, auditContext);
        var service = new MagicLinkSignInService(dependencies, Options.Create(options ?? new MagicLinkSignInOptions()));
        return new Fixture(service, repository, emailSender, audit, time, tokenHasher, rateLimiter, events);
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
                    return Result.Success(CreateHandshakeCreated(handshake, "mfa-token"));
                });
        }

        return new AuthenticationOrchestrator(pipeline, Mock.Of<IAuthenticationFactorPipeline>(), handshakes.Object, new TestAuthenticationHandshakeCompletionService(), policy, Mock.Of<IAuthenticationProviderRegistry>());
    }

    private static string ExtractToken(string? body)
    {
        ArgumentNullException.ThrowIfNull(body);
        var uri = new Uri(body.Split(' ').Last());
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        return query["token"] ?? throw new AssertionException("Token not found in email body.");
    }

    private static string AllAuditText(Fixture fixture)
    {
        return string.Join("|", fixture.Audit.Events.SelectMany(e => new[] { e.EventType, e.FailureReason }.Concat(e.Properties?.Values ?? [])));
    }

    private sealed record Fixture(MagicLinkSignInService Service, InMemoryUserCredentialStore Repository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time, ISecureTokenHasher TokenHasher, StubRateLimiter RateLimiter, List<string> Events);

    private static string ExpectedRateLimitKey(string purpose, string dimensionName, string dimensionValue)
    {
        var composed = string.Join('|',
            EncodeRateLimitKeySegment(purpose),
            EncodeRateLimitKeySegment(AuthenticationRateLimitKeyBuilder.NormalizeProviderSelector(AuthenticationProviderKey.MagicLink)),
            EncodeRateLimitKeySegment("global"),
            EncodeRateLimitKeySegment(dimensionName),
            EncodeRateLimitKeySegment(dimensionValue));
        return AuthenticationRateLimitKeyBuilder.HashKey(composed);
    }

    private static string EncodeRateLimitKeySegment(string value) => $"{value.Length}:{value}";

    private sealed class StubRateLimiter(bool requestAllowed, bool verifyAllowed, TimeProvider timeProvider) : IAuthenticationRateLimiter
    {
        public List<RateLimitAttempt> Attempts { get; } = [];
        public HashSet<string> BlockedKeys { get; } = [];

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            Attempts.Add(attempt);
            var allowed = (attempt.Purpose == "magic-link-request" ? requestAllowed : verifyAllowed)
                && !BlockedKeys.Contains(attempt.Key);
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

    private class RecordingEmailSender(List<string>? events = null) : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            events?.Add("send");
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingTransactionalEmailSender(List<string> events) : RecordingEmailSender(events), ITransactionalEmailOutboxSender;

    private sealed class RecordingTransactionProvider(List<string> events) : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IAshlarTransaction>(new RecordingTransaction(events));
        }
    }

    private sealed class RecordingTransaction(List<string> events) : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];

        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            events.Add("commit");
            foreach (var hook in _hooks)
            {
                await hook(cancellationToken);
            }
        }

        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            _hooks.Clear();
            return Task.CompletedTask;
        }

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            _hooks.Add(action);
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
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

    private static AuthenticationHandshakeCreated CreateHandshakeCreated(AuthenticationHandshake handshake, string token)
    {
        return new AuthenticationHandshakeCreated(
            new CreatedAuthenticationHandshake(
                handshake.Id,
                handshake.UserId,
                handshake.TenantId,
                handshake.CreatedAt,
                handshake.ExpiresAt,
                handshake.RequiredFactors,
                handshake.Metadata),
            token);
    }

    private sealed class InMemoryUserCredentialStore(params User?[] users) : IUserRepository, ICredentialRepository
    {
        private readonly List<User> _users = users.OfType<User>().ToList();
        public List<UserCredential> Credentials { get; } = [];
        public int GetUserByEmailCalls { get; private set; }

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            GetUserByEmailCalls++;
            var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
            return Task.FromResult<IUser?>(_users.SingleOrDefault(user => IdentityNormalization.NormalizeEmail(user.DisplayEmail) == normalizedEmail));
        }
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
