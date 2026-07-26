using System.Globalization;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity.Features.Credentials;

internal sealed class PasswordResetServiceTests
{
    private const string OldPassword = "old-password";
    private const string NewPassword = "new-password";

    [Test]
    public void ConstructorRejectsNullDependencies()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PasswordResetService(null!));
    }

    [Test]
    public void ConstructorUsesDefaultOptionsWhenOptionsAreNull()
    {
        var fixture = CreateFixture(CreateUser());

        var service = new PasswordResetService(fixture.Dependencies, options: null);

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task RequestPasswordResetAsyncStoresOnlyHashedTokenAndSendsEmail()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var message = fixture.EmailSender.Messages.Single();
        var credential = fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Internal);
        var token = ExtractQueryValue(message.TextBody!, "t");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(message.To, Is.EqualTo(user.DisplayEmail));
            Assert.That(message.TextBody, Does.Contain(token));
            Assert.That(credential.ProviderName, Is.EqualTo(PasswordResetService.ProviderName));
            Assert.That(credential.ProviderKey, Is.EqualTo(new Sha256TokenHasher().HashToken(token)));
            Assert.That(credential.ProviderKey, Is.Not.EqualTo(token));
            Assert.That(credential.CredentialValue, Is.Null);
            Assert.That(credential.Purpose, Is.EqualTo(PasswordResetService.CredentialPurpose));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequested), Is.True);
            Assert.That(message.Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [TestCase(null, "user_missing")]
    [TestCase(false, "user_disabled")]
    public async Task RequestPasswordResetAsyncSuppressesMissingAndDisabledUsers(bool? active, string _)
    {
        var user = active.HasValue ? CreateUser(active.Value ? UserAccountState.Active : UserAccountState.Disabled) : null;
        var fixture = CreateFixture(user, includeLocalPassword: active == true);

        var result = await fixture.Service.RequestPasswordResetAsync("user@example.com", new Uri("https://example.com/reset"));
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequestSuppressed);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Store.Credentials.All(c => c.ProviderType != ProviderType.Internal), Is.True);
            Assert.That(securityEvent.FailureReason, Is.EqualTo("request_suppressed"));
            Assert.That(securityEvent.UserId, Is.Null);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncSuppressesUserWithoutLocalPassword()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user, includeLocalPassword: false);

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var securityEvent = fixture.Audit.Events.Single(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequestSuppressed);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(securityEvent.FailureReason, Is.EqualTo("request_suppressed"));
            Assert.That(securityEvent.UserId, Is.Null);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncRejectsInvalidCallbackUri()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        fixture.UriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(false);

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://evil.example/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidCallbackUri));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Audit.Events.Single().EventType, Is.EqualTo(AshlarSecurityEventTypes.PasswordResetFailed));
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncRejectsBlankEmail()
    {
        var fixture = CreateFixture(CreateUser());

        var result = await fixture.Service.RequestPasswordResetAsync(" ", new Uri("https://example.com/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(fixture.RateLimiter.Attempts, Is.Empty);
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Audit.Events, Is.Empty);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncReturnsRateLimitedWhenRequestLimitIsExceeded()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        fixture.RateLimiter.BlockedKeys.Add(ExpectedRateLimitKey("password-reset-request", "email", "email:USER@EXAMPLE.COM"));

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequestRateLimited), Is.True);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncConsumesTokenReplacesPasswordAndRevokesSessions()
    {
        var user = CreateUser(tenantId: Guid.NewGuid());
        var fixture = CreateFixture(user);
        var context = new AuthenticationContext(TenantId: user.TenantId);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), context);
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        fixture.Audit.Events.Clear();

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, context);
        var passwordCredential = fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Local && c.Status == CredentialStatus.Active);
        var provider = new LocalPasswordProvider(new PasswordHasherSelector([new PasswordHasherV1()]));
        var oldPasswordResult = await provider.AuthenticateAsync(new LocalPasswordAssertion(OldPassword), passwordCredential);
        var newPasswordResult = await provider.AuthenticateAsync(new LocalPasswordAssertion(NewPassword), passwordCredential);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True, result.FailureReason);
            Assert.That(result.Value?.UserId, Is.EqualTo(user.Id));
            Assert.That(result.Value?.SessionsRevoked, Is.EqualTo(2));
            Assert.That(fixture.Store.Credentials.Any(c => c.ProviderType == ProviderType.Internal), Is.False);
            Assert.That(oldPasswordResult.Status, Is.EqualTo(AuthenticationResultStatus.Failed));
            Assert.That(newPasswordResult.Status, Is.EqualTo(AuthenticationResultStatus.Succeeded));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetCompleted), Is.True);
            Assert.That(fixture.Notifications.Notifications.Single().Type, Is.EqualTo(SecurityNotificationType.PasswordResetCompleted));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRejectsTenantUserTokenWhenContextTenantIsOmitted()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser(tenantId: tenantId);
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), new AuthenticationContext(TenantId: tenantId));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(fixture.Store.Credentials.Any(c => c.ProviderType == ProviderType.Internal), Is.True);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRejectsTenantUserTokenWhenContextTenantDiffers()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser(tenantId: tenantId);
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), new AuthenticationContext(TenantId: tenantId));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var result = await fixture.Service.ResetPasswordAsync(
            new PasswordResetRequest { Token = token, NewPassword = NewPassword },
            new AuthenticationContext(TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(fixture.Store.Credentials.Any(c => c.ProviderType == ProviderType.Internal), Is.True);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncCanLeaveSessionsActiveWhenConfigured()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user, configure: options => options.RevokeSessions = false);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.SessionsRevoked, Is.Zero);
            Assert.That(fixture.Sessions.RevokeAllCount, Is.Zero);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRevokesRememberedMfaDevices()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser(tenantId: tenantId);
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor { RevokeAllResult = 2 };
        var fixture = CreateFixture(user, configure: options => options.RevokeSessions = false, rememberedMfaDeviceService: rememberedDevices);
        var context = new AuthenticationContext(TenantId: tenantId, IpAddress: "203.0.113.10", UserAgent: "unit-test", CorrelationId: "corr");
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), context);
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.Sessions.RevokeAllCount, Is.Zero);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rememberedDevices.LastRequest?.Tenant?.TenantId, Is.EqualTo(tenantId));
            Assert.That(rememberedDevices.LastRequest?.Reason, Is.EqualTo("Password reset"));
            Assert.That(rememberedDevices.LastRequest?.Audit?.ActorUserId, Is.EqualTo(user.Id));
            Assert.That(rememberedDevices.LastRequest?.Audit?.IpAddress, Is.EqualTo("203.0.113.10"));
            Assert.That(rememberedDevices.LastRequest?.Audit?.UserAgent, Is.EqualTo("unit-test"));
            Assert.That(rememberedDevices.LastRequest?.Audit?.CorrelationId, Is.EqualTo("corr"));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRevokesSessionsWithinUserTenant()
    {
        var tenantId = Guid.NewGuid();
        var user = CreateUser(tenantId: tenantId);
        var fixture = CreateFixture(user);
        var context = new AuthenticationContext(TenantId: tenantId);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), context);
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.Sessions.RevokeAllCount, Is.EqualTo(1));
            Assert.That(fixture.Sessions.LastTenant?.TenantId, Is.EqualTo(tenantId));
            Assert.That(fixture.Sessions.LastIncludeAllTenants, Is.False);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRevokesRememberedMfaDevicesForGlobalUser()
    {
        var user = CreateUser();
        var rememberedDevices = new TestRememberedMfaDeviceMutationExecutor { RevokeAllResult = 1 };
        var fixture = CreateFixture(user, rememberedMfaDeviceService: rememberedDevices);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(rememberedDevices.LastRequest?.Tenant, Is.Null);
            Assert.That(rememberedDevices.LastRequest?.Reason, Is.EqualTo("Password reset"));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRejectsExpiredConsumedRevokedMalformedAndWrongPurposeTokens()
    {
        await AssertResetFailureAsync(fixture => fixture.Time.Advance(TimeSpan.FromHours(3)), AshlarFailureCodes.InvalidOrExpiredToken);
        await AssertResetFailureAsync(fixture => _ = fixture.Store.ConsumeCredentialAsync(fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Internal).Id, fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Internal).Version), AshlarFailureCodes.InvalidOrExpiredToken);
        await AssertResetFailureAsync(fixture =>
        {
            var credential = fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Internal);
            credential.Status = CredentialStatus.Revoked;
            credential.RevokedAt = fixture.Time.GetUtcNow();
        }, AshlarFailureCodes.InvalidOrExpiredToken);
        await AssertResetFailureAsync(fixture => fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Internal).Purpose = "email-verification", AshlarFailureCodes.InvalidOrExpiredToken);

        var malformed = CreateFixture(CreateUser());
        var malformedResult = await malformed.Service.ResetPasswordAsync(new PasswordResetRequest { Token = new string('a', 257), NewPassword = NewPassword });
        var malformedWithIp = await malformed.Service.ResetPasswordAsync(new PasswordResetRequest { Token = new string('a', 257), NewPassword = NewPassword }, new AuthenticationContext(IpAddress: "203.0.113.10"));
        var malformedWithCorrelation = await malformed.Service.ResetPasswordAsync(new PasswordResetRequest { Token = new string('a', 257), NewPassword = NewPassword }, new AuthenticationContext(CorrelationId: "corr"));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(malformedResult.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(malformedWithIp.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(malformedWithCorrelation.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncReturnsRateLimitedForOverlongTokenWhenSourceLimitIsExceeded()
    {
        var fixture = CreateFixture(CreateUser());
        fixture.RateLimiter.BlockedKeys.Add(ExpectedRateLimitKey("password-reset-verify", "source", "source:ip:203.0.113.41"));

        var result = await fixture.Service.ResetPasswordAsync(
            new PasswordResetRequest { Token = new string('a', 257), NewPassword = NewPassword },
            new AuthenticationContext(IpAddress: "203.0.113.41"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetVerificationRateLimited), Is.True);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncReturnsRateLimitedWhenSourceLimitIsExceeded()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        fixture.RateLimiter.BlockedKeys.Add(ExpectedRateLimitKey("password-reset-request", "source", "source:ip:203.0.113.40"));

        var result = await fixture.Service.RequestPasswordResetAsync(
            user.DisplayEmail,
            new Uri("https://example.com/reset"),
            new AuthenticationContext(IpAddress: "203.0.113.40"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.RateLimiter.Attempts.Select(a => a.Key), Does.Not.Contain("password-reset-request:email:USER@EXAMPLE.COM"));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequestRateLimited), Is.True);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncRevokesTokenAndReturnsGenericSuccessWhenEmailSendFailsAfterCommit()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        fixture.EmailSender.ThrowOnSend = true;

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequested), Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetFailed && e.FailureReason == "delivery_failed"), Is.True);
            Assert.That(fixture.Store.Credentials.Any(c => c.ProviderType == ProviderType.Internal && c.ProviderName == PasswordResetService.ProviderName && c.Status == CredentialStatus.Active), Is.False);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncDoesNotThrowWhenPostCommitRevocationAuditThrows()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user, transactionAwareStore: true);
        fixture.EmailSender.ThrowOnSend = true;
        fixture.Audit.ThrowOnPasswordResetDeliveryFailure = true;

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.Store.Credentials.Any(c =>
                c.ProviderType == ProviderType.Internal &&
                c.ProviderName == PasswordResetService.ProviderName &&
                c.Status == CredentialStatus.Active), Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetFailed && e.FailureReason == "delivery_failed"), Is.False);
        }
    }


    [Test]
    public async Task RequestPasswordResetAsyncDoesNotRecordRequestedSuccessWhenTransactionalOutboxEnqueueFails()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user, transactionalEmailSender: true);
        fixture.EmailSender.ThrowOnSend = true;

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequested), Is.False);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetFailed && e.FailureReason == "delivery_failed"), Is.True);
            Assert.That(fixture.Store.Credentials.Any(c => c.ProviderType == ProviderType.Internal && c.ProviderName == PasswordResetService.ProviderName && c.Status == CredentialStatus.Active), Is.False);
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncRecordsRequestedSuccessWhenTransactionalOutboxEnqueueSucceeds()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user, transactionalEmailSender: true);

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetRequested), Is.True);
            Assert.That(fixture.EmailSender.Messages.Single().Sensitivity, Is.EqualTo(EmailMessageSensitivity.ContainsLiveSecret));
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncPadsSuppressedRequestDuration()
    {
        var fixture = CreateFixture(null, configure: options => options.MinimumRequestDuration = TimeSpan.FromSeconds(5));

        var resultTask = fixture.Service.RequestPasswordResetAsync("missing@example.com", new Uri("https://example.com/reset"));

        Assert.That(resultTask.IsCompleted, Is.False);

        fixture.Time.Advance(TimeSpan.FromSeconds(5));
        var result = await resultTask;

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task RequestPasswordResetAsyncDoesNotPadWhenWorkExceedsMinimumDuration()
    {
        var fixture = CreateFixture(CreateUser(), configure: options => options.MinimumRequestDuration = TimeSpan.FromSeconds(1));
        fixture.EmailSender.OnSend = () => fixture.Time.Advance(TimeSpan.FromSeconds(2));

        var result = await fixture.Service.RequestPasswordResetAsync("user@example.com", new Uri("https://example.com/reset"));

        Assert.That(result.Succeeded, Is.True);
    }

    [TestCase(null)]
    [TestCase(" ")]
    public async Task ResetPasswordAsyncRejectsMissingTokenWithGenericFailure(string? token)
    {
        var fixture = CreateFixture(CreateUser());

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(result.FailureMessage, Is.EqualTo("Invalid or expired token."));
            Assert.That(fixture.Store.Credentials.Any(credential =>
                credential.ProviderType == ProviderType.Internal &&
                credential.ProviderName == PasswordResetService.ProviderName &&
                credential.Purpose == PasswordResetService.CredentialPurpose), Is.False);
            Assert.That(fixture.Audit.Events.Single().FailureReason, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken.Value));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRejectsBlankPasswordAndConsumeConcurrencyFailure()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var blankPassword = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = " " });
        fixture.Store.ConsumeSucceeds = false;
        var consumeFailure = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(blankPassword.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidSecret));
            Assert.That(consumeFailure.FailureCode, Is.EqualTo(AshlarFailureCodes.TokenConsumptionFailed));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRejectsWrongProviderAndWrongTenant()
    {
        var user = CreateUser(tenantId: Guid.NewGuid());
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), new AuthenticationContext(TenantId: user.TenantId));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        var credential = fixture.Store.Credentials.Single(c => c.ProviderType == ProviderType.Internal);
        fixture.Store.Credentials.Remove(credential);
        fixture.Store.Credentials.Add(new UserCredential
        {
            Id = credential.Id,
            UserId = credential.UserId,
            ProviderType = credential.ProviderType,
            ProviderName = "email-verification",
            ProviderKey = credential.ProviderKey,
            Version = credential.Version,
            CreatedAt = credential.CreatedAt,
            ExpiresAt = credential.ExpiresAt,
            Status = credential.Status,
            Purpose = credential.Purpose
        });

        var wrongProvider = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, new AuthenticationContext(TenantId: user.TenantId));

        fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), new AuthenticationContext(TenantId: user.TenantId));
        token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        var wrongTenant = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, new AuthenticationContext(TenantId: Guid.NewGuid()));

        var tenantlessUser = CreateUser();
        fixture = CreateFixture(tenantlessUser);
        await fixture.Service.RequestPasswordResetAsync(tenantlessUser.DisplayEmail, new Uri("https://example.com/reset"));
        token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        var tenantRequiredForTenantlessUser = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, new AuthenticationContext(TenantId: Guid.NewGuid()));

        var nonTenantUser = new NonTenantUser { Id = Guid.NewGuid(), DisplayEmail = "plain@example.com", AccountState = UserAccountState.Active };
        fixture = CreateFixture(nonTenantUser);
        await fixture.Service.RequestPasswordResetAsync(nonTenantUser.DisplayEmail, new Uri("https://example.com/reset"));
        token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        var tenantRequiredForNonTenantUser = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword }, new AuthenticationContext(TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongProvider.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(wrongTenant.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(tenantRequiredForTenantlessUser.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(tenantRequiredForNonTenantUser.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncIsSingleUseAndReportsRateLimitedVerification()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        var first = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });
        var replay = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = "another-password" });

        var limited = CreateFixture(user, verifyAllowed: false);
        var limitedResult = await limited.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Succeeded, Is.True);
            Assert.That(replay.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(limitedResult.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(limited.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetVerificationRateLimited), Is.True);
        }
    }

    [Test]
    public async Task PasswordResetDoesNotStoreRawTokenOrPasswordOutsideResetEmail()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");

        await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        var credentialText = string.Join("|", fixture.Store.Credentials.Select(c => string.Join("|", c.ProviderKey, c.CredentialValue, c.Metadata, c.Purpose)));
        var eventText = string.Join("|", fixture.Audit.Events.Select(e => string.Join("|", e.EventType, e.FailureReason, e.Provider?.ToString(), e.Properties == null ? string.Empty : string.Join("|", e.Properties.Values))));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages.Single().TextBody, Does.Contain(token));
            Assert.That(credentialText, Does.Not.Contain(token));
            Assert.That(credentialText, Does.Not.Contain(NewPassword));
            Assert.That(eventText, Does.Not.Contain(token));
            Assert.That(eventText, Does.Not.Contain(NewPassword));
        }
    }

    [Test]
    public async Task ResetTokenCredentialDoesNotAppearAsPrimaryPasswordPosture()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));

        var sessionService = new TestAuthenticationSessionMutationExecutor();
        var localProvider = new Mock<IPrimaryAuthenticationProvider>();
        localProvider.SetupGet(provider => provider.Key).Returns(AuthenticationProviderKey.Local);
        var providerRegistry = new AuthenticationProviderRegistry([localProvider.Object]);
        var composition = new DurableSecurityMutationTestComposition(fixture.Audit, fixture.Store, fixture.Store);

        var accountSecurity = new AccountSecurityService(
            fixture.Store,
            fixture.Store,
            sessionService,
            new TestAuthenticationSessionReader(),
            composition.Transactions,
            new PermissiveAccountSecurityGuard(),
            new AccountSecurityServiceDependencies(fixture.Time, composition.Events, ProviderRegistry: providerRegistry));

        var posture = await ((IAccountSecurityPostureReader)accountSecurity).GetUserSecurityPostureAsync(
            user.Id, new AccountSecurityPostureRequest());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(posture.Succeeded, Is.True);
            Assert.That(posture.Value?.PrimaryCredentials.Count(c => c.Provider.Type == ProviderType.Local), Is.EqualTo(1));
            Assert.That(posture.Value?.PrimaryCredentials.Any(c => c.Provider.Type == ProviderType.Internal), Is.False);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncReturnsRateLimitedWhenTokenLimitIsExceeded()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        var tokenHash = new Sha256TokenHasher().HashToken(token);
        fixture.RateLimiter.BlockedKeys.Add(ExpectedRateLimitKey("password-reset-verify", "token-hash", $"token:{tokenHash}"));

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetVerificationRateLimited), Is.True);
        }
    }

    [Test]
    public async Task ResetPasswordAsyncRateLimitsVerificationByContextKey()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        fixture.RateLimiter.Attempts.Clear();

        var result = await fixture.Service.ResetPasswordAsync(
            new PasswordResetRequest { Token = token, NewPassword = NewPassword },
            new AuthenticationContext(IpAddress: "203.0.113.20"));

        var verifyAttempts = fixture.RateLimiter.Attempts.Where(a => a.Purpose == "password-reset-verify").ToList();
        var tokenHash = fixture.Dependencies.TokenContext.Hasher.HashToken(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(verifyAttempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("password-reset-verify", "source", "source:ip:203.0.113.20")));
            Assert.That(verifyAttempts.Select(a => a.Key), Does.Contain(ExpectedRateLimitKey("password-reset-verify", "token-hash", $"token:{tokenHash}")));
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncCarriesContextUserIdIntoRateLimitAttempt()
    {
        var user = CreateUser();
        var actorUserId = Guid.NewGuid();
        var fixture = CreateFixture(user);

        var result = await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"), new AuthenticationContext(UserId: actorUserId));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.RateLimiter.Attempts.Where(a => a.Purpose == "password-reset-request").Select(a => a.UserId), Is.All.EqualTo(actorUserId.ToString()));
        }
    }

    [Test]
    public async Task RequestPasswordResetAsyncRateLimitsByEmailAndSource()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);

        var result = await fixture.Service.RequestPasswordResetAsync(
            user.DisplayEmail,
            new Uri("https://example.com/reset"),
            new AuthenticationContext(IpAddress: "203.0.113.30"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(fixture.RateLimiter.Attempts, Has.Count.EqualTo(2));
            Assert.That(fixture.RateLimiter.Attempts[0].Key, Is.EqualTo(ExpectedRateLimitKey("password-reset-request", "source", "source:ip:203.0.113.30")));
            Assert.That(fixture.RateLimiter.Attempts[1].Key, Is.EqualTo(ExpectedRateLimitKey("password-reset-request", "email", "email:USER@EXAMPLE.COM")));
        }
    }

    [Test]
    public async Task ResetPasswordAsyncShouldRejectUserThatBecomesUnavailableAfterMutationLock()
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        fixture.Store.OnMutationLock = () => fixture.Store.Users.Clear();

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidOrExpiredToken));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetFailed), Is.True);
        }
    }

    private static async Task AssertResetFailureAsync(Action<Fixture> mutate, AshlarFailureCode expectedCode)
    {
        var user = CreateUser();
        var fixture = CreateFixture(user);
        await fixture.Service.RequestPasswordResetAsync(user.DisplayEmail, new Uri("https://example.com/reset"));
        var token = ExtractQueryValue(fixture.EmailSender.Messages.Single().TextBody!, "t");
        mutate(fixture);

        var result = await fixture.Service.ResetPasswordAsync(new PasswordResetRequest { Token = token, NewPassword = NewPassword });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(expectedCode));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.PasswordResetFailed), Is.True);
        }
    }

    private static Fixture CreateFixture(
        IUser? user,
        bool includeLocalPassword = true,
        bool requestAllowed = true,
        bool verifyAllowed = true,
        Action<PasswordResetOptions>? configure = null,
        bool transactionalEmailSender = false,
        IRememberedMfaDeviceMutationExecutor? rememberedMfaDeviceService = null,
        bool transactionAwareStore = false)
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-05-25T12:00:00Z", CultureInfo.InvariantCulture));
        var store = new InMemoryUserCredentialStore(time);
        if (user != null)
        {
            store.Users.Add(user);
            if (includeLocalPassword)
            {
                store.Credentials.Add(CreatePasswordCredential(user.Id, OldPassword, time.GetUtcNow()));
            }
        }

        var rateLimiter = new RecordingRateLimiter(requestAllowed, verifyAllowed);
        RecordingEmailSender emailSender = transactionalEmailSender ? new RecordingTransactionalEmailSender() : new RecordingEmailSender();
        var uriValidator = new Mock<IUriValidator>();
        uriValidator.Setup(v => v.IsValid(It.IsAny<Uri?>())).Returns(true);
        var audit = new RecordingSecurityEventSink();
        var notifications = new RecordingSecurityNotificationService();
        IAshlarTransactionProvider transactionProvider = transactionAwareStore
            ? new SnapshotTransactionProvider(store)
            : AshlarDurableTransactionProvider.Create(new NullTransactionProvider());
        var identityContext = new IdentityContext(store, store, Mock.Of<IIdentityService>(), AshlarDurableTransactionProvider.Create(transactionProvider));
        var infrastructure = new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator.Object);
        var auditContext = new IdentityAuditContext(time, audit, notifications);
        var dependencies = new PasswordResetDependencies(
            identityContext,
            new SecureTokenContext(new SecureTokenGenerator(), new Sha256TokenHasher()),
            infrastructure,
            new RecordingSessionRepository(),
            new PasswordHasherSelector([new PasswordHasherV1()]),
            auditContext,
            rememberedMfaDeviceService);
        var options = new PasswordResetOptions { MinimumRequestDuration = TimeSpan.Zero };
        configure?.Invoke(options);
        var service = new PasswordResetService(dependencies, Options.Create(options));

        return new Fixture(service, dependencies, store, emailSender, rateLimiter, uriValidator, audit, notifications, (RecordingSessionRepository)dependencies.SessionRepository, time);
    }

    private static AshlarUser CreateUser(UserAccountState accountState = UserAccountState.Active, Guid? tenantId = null)
    {
        return new AshlarUser { Id = Guid.NewGuid(), DisplayEmail = "user@example.com", AccountState = accountState, TenantId = tenantId };
    }

    private static UserCredential CreatePasswordCredential(Guid userId, string password, DateTimeOffset now)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Local,
            ProviderName = AuthenticationProviderKey.Local.Name,
            ProviderKey = userId.ToString("D"),
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = now,
            Status = CredentialStatus.Active,
            CredentialValue = Convert.ToBase64String(new PasswordHasherV1().HashPassword(password))
        };
    }

    private static string ExtractQueryValue(string text, string name)
    {
        var uriStart = text.IndexOf("http", StringComparison.Ordinal);
        Assert.That(uriStart, Is.GreaterThanOrEqualTo(0));
        var uriText = text[uriStart..].Split([' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)[0];
        var uri = new Uri(uriText);
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (var item in query)
        {
            var parts = item.Split('=', 2);
            if (parts.Length == 2 && parts[0] == name)
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        Assert.Fail($"Query parameter '{name}' was not found.");
        return string.Empty;
    }

    private sealed record Fixture(
        PasswordResetService Service,
        PasswordResetDependencies Dependencies,
        InMemoryUserCredentialStore Store,
        RecordingEmailSender EmailSender,
        RecordingRateLimiter RateLimiter,
        Mock<IUriValidator> UriValidator,
        RecordingSecurityEventSink Audit,
        RecordingSecurityNotificationService Notifications,
        RecordingSessionRepository Sessions,
        FakeTimeProvider Time);

    private static string ExpectedRateLimitKey(string purpose, string dimensionName, string dimensionValue)
    {
        var composed = string.Join('|',
            EncodeRateLimitKeySegment(purpose),
            EncodeRateLimitKeySegment("local:local"),
            EncodeRateLimitKeySegment("global"),
            EncodeRateLimitKeySegment(dimensionName),
            EncodeRateLimitKeySegment(dimensionValue));
        return AuthenticationRateLimitKeyBuilder.HashKey(composed);
    }

    private static string EncodeRateLimitKeySegment(string value) => $"{value.Length}:{value}";

    private class RecordingEmailSender : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];
        public bool ThrowOnSend { get; set; }
        public Action? OnSend { get; set; }
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            if (ThrowOnSend)
            {
                throw new InvalidOperationException("Email send failed.");
            }

            OnSend?.Invoke();
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingTransactionalEmailSender : RecordingEmailSender, ITransactionalEmailOutboxSender;

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];
        public bool ThrowOnPasswordResetDeliveryFailure { get; set; }

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            if (ThrowOnPasswordResetDeliveryFailure &&
                securityEvent.EventType == AshlarSecurityEventTypes.PasswordResetFailed &&
                securityEvent.FailureReason == "delivery_failed")
            {
                throw new InvalidOperationException("audit failed");
            }

            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class SnapshotTransactionProvider(InMemoryUserCredentialStore store) : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IAshlarTransaction>(new SnapshotTransaction(store));
        }

        private sealed class SnapshotTransaction(InMemoryUserCredentialStore store) : IAshlarTransaction
        {
            private readonly List<UserCredential> _credentials = store.Credentials.Select(static credential => credential.Clone()).ToList();
            private readonly List<Func<CancellationToken, Task>> _hooks = [];
            private bool _committed;
            private bool _disposed;

            public async Task CommitAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ObjectDisposedException.ThrowIf(_disposed, this);
                _committed = true;
                _disposed = true;

                foreach (var hook in _hooks)
                {
                    try
                    {
                        await hook(CancellationToken.None);
                    }
                    catch (Exception)
                    {
                        // Test transaction mirrors provider commits: post-commit hook failures do not undo commit.
                    }
                }
            }

            public Task RollbackAsync(CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ObjectDisposedException.ThrowIf(_disposed, this);
                Restore();
                _disposed = true;
                return Task.CompletedTask;
            }

            public void OnCommitted(Func<CancellationToken, Task> action)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _hooks.Add(action ?? throw new ArgumentNullException(nameof(action)));
            }

            public ValueTask DisposeAsync()
            {
                if (!_disposed && !_committed)
                {
                    Restore();
                }

                _disposed = true;
                return ValueTask.CompletedTask;
            }

            private void Restore()
            {
                store.Credentials.Clear();
                store.Credentials.AddRange(_credentials.Select(static credential => credential.Clone()));
            }
        }
    }

    private sealed class RecordingSecurityNotificationService : ISecurityNotificationService
    {
        public List<SecurityNotification> Notifications { get; } = [];
        public Task<SecurityNotificationResult> NotifyAsync(SecurityNotification notification, CancellationToken cancellationToken = default)
        {
            Notifications.Add(notification);
            return Task.FromResult(SecurityNotificationResult.Success());
        }
    }

    private sealed class RecordingRateLimiter(bool requestAllowed, bool verifyAllowed) : IAuthenticationRateLimiter
    {
        public List<RateLimitAttempt> Attempts { get; } = [];
        public HashSet<string> BlockedKeys { get; } = [];
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            Attempts.Add(attempt);
            var allowed = !BlockedKeys.Contains(attempt.Key) && (attempt.Purpose == "password-reset-request" ? requestAllowed : verifyAllowed);
            return Task.FromResult(new RateLimitDecision
            {
                Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
                Remaining = allowed ? 1 : 0,
                WindowResetAt = DateTimeOffset.UtcNow.AddMinutes(1)
            });
        }
    }

    private sealed class InMemoryUserCredentialStore(TimeProvider timeProvider) : IUserRepository, ICredentialRepository
    {
        public Action? OnMutationLock { get; set; }
        public Task AcquireUserMutationLockAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            OnMutationLock?.Invoke();
            return Task.CompletedTask;
        }

        public List<IUser> Users { get; } = [];
        public List<UserCredential> Credentials { get; } = [];
        public bool ConsumeSucceeds { get; set; } = true;

        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            var normalizedEmail = IdentityNormalization.NormalizeEmail(email);
            return Task.FromResult<IUser?>(Users.SingleOrDefault(user =>
                IdentityNormalization.NormalizeEmail(user.DisplayEmail) == normalizedEmail
                && (user as ITenantUser)?.TenantId == tenantId));
        }

        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(Users.SingleOrDefault(user => user.Id == userId));
        }

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
        {
            var now = timeProvider.GetUtcNow();
            var credential = Credentials.SingleOrDefault(c =>
                c.ProviderType == type
                && c.ProviderName == providerName
                && c.ProviderKey == providerKey
                && c.IsAvailable(now));

            return Task.FromResult<IUser?>(credential == null ? null : Users.SingleOrDefault(user => user.Id == credential.UserId));
        }

        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) => throw new NotImplementedException();

        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default)
        {
            var credential = Credentials
                .Where(c =>
                    c.UserId == userId
                    && c.ProviderType == type
                    && c.ProviderName == providerName
                    && (providerKey == null || c.ProviderKey == providerKey)
                    && c.Status == CredentialStatus.Active
                    && c.RevokedAt == null)
                .OrderByDescending(c => c.CreatedAt)
                .ThenBy(c => c.Id)
                .FirstOrDefault();

            return Task.FromResult(credential);
        }

        public Task<IReadOnlyList<UserCredential>> ListCredentialsForUserAsync(Guid userId, bool activeOnly = true, CancellationToken cancellationToken = default)
        {
            var now = timeProvider.GetUtcNow();
            var credentials = Credentials
                .Where(c => c.UserId == userId && (!activeOnly || c.IsAvailable(now)))
                .Select(c =>
                {
                    var clone = c.Clone();
                    clone.CredentialValue = null;
                    return clone;
                })
                .ToList()
                .AsReadOnly();

            return Task.FromResult<IReadOnlyList<UserCredential>>(credentials);
        }

        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
        {
            Credentials.Add(credential);
            return Task.CompletedTask;
        }

        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default)
        {
            var existing = Credentials.SingleOrDefault(c =>
                c.ProviderType == credential.ProviderType
                && c.ProviderName == credential.ProviderName
                && c.ProviderKey == credential.ProviderKey);

            if (existing != null && existing.UserId != credential.UserId)
            {
                throw new CredentialProviderKeyConflictException();
            }

            if (existing != null)
            {
                Credentials.Remove(existing);
            }

            Credentials.Add(credential);
            return Task.CompletedTask;
        }

        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => throw new NotImplementedException();

        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default)
        {
            var credential = Credentials.SingleOrDefault(c => c.Id == credentialId && c.Version == expectedVersion);
            if (!ConsumeSucceeds || credential == null)
            {
                return Task.FromResult(false);
            }

            Credentials.Remove(credential);
            return Task.FromResult(true);
        }

        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default)
        {
            var now = timeProvider.GetUtcNow();
            var toRevoke = Credentials.Where(c =>
                c.UserId == userId
                && c.ProviderType == type
                && c.ProviderName == providerName
                && c.Status == CredentialStatus.Active
                && c.RevokedAt == null).ToList();

            foreach (var credential in toRevoke)
            {
                credential.Status = CredentialStatus.Revoked;
                credential.RevokedAt = now;
                credential.UpdatedAt = now;
                credential.Version = Guid.NewGuid().ToString("N");
            }

            return Task.FromResult(toRevoke.Count);
        }
    }

    private sealed class RecordingSessionRepository : IAuthenticationSessionRepository
    {
        public int RevokeAllCount { get; private set; }
        public TenantContext? LastTenant { get; private set; }
        public bool LastIncludeAllTenants { get; private set; }

        public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<AuthenticationSession?> MarkStepUpVerifiedAsync(Guid sessionId, Guid userId, DateTimeOffset verifiedAt, AuthenticationProviderKey verifiedProvider, string verifiedFactor, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default)
        {
            RevokeAllCount++;
            LastTenant = tenant;
            LastIncludeAllTenants = includeAllTenants;
            return Task.FromResult(2);
        }

        public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AuthenticationSession>>([]);
        }

        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, bool includeAllTenants = false, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, bool includeAllTenants = false, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    }

    private sealed class TestRememberedMfaDeviceMutationExecutor : IRememberedMfaDeviceMutationExecutor
    {
        public int RevokeAllResult { get; set; }
        public RevokeAllRememberedMfaDevicesRequest? LastRequest { get; private set; }
        public Task<bool> RevokeAsync(Guid userId, RevokeRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<int> RevokeAllAsync(Guid userId, RevokeAllRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default) { LastRequest = request; return Task.FromResult(RevokeAllResult); }
    }

    private sealed class TestAuthenticationSessionMutationExecutor : IAuthenticationSessionMutationExecutor
    {
        public Task<int> RevokeSessionsForUserAsync(Guid userId, RevokeAuthenticationSessionsForUserRequest request, CancellationToken cancellationToken = default) => Task.FromResult(0);
        public Task<bool> RevokeSessionForUserAsync(Guid userId, RevokeAuthenticationSessionRequest request, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<int> RevokeOtherSessionsAsync(Guid userId, RevokeOtherAuthenticationSessionsRequest request, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class TestAuthenticationSessionReader : IAuthenticationSessionInventoryReader
    {
        public Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsAsync(ValidatedAuthenticationSession session, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success<IReadOnlyList<AuthenticationSessionSummary>>([]));

        public Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsForUserAsync(Guid userId, Guid? tenantId, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success<IReadOnlyList<AuthenticationSessionSummary>>([]));
    }

    private sealed class NonTenantUser : IUser
    {
        public required Guid Id { get; init; }
        public required string DisplayEmail { get; init; }
        public string? Name { get; init; }
        public UserAccountState AccountState { get; init; } = UserAccountState.Active;
        public DateTimeOffset? EmailVerifiedAt { get; init; }
    }
}
