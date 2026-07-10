using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Mfa;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Tenants;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarRememberedMfaDeviceCookieManagerTests
{
    [Test]
    public void OptionsShouldUseSecureDefaults()
    {
        var options = new AshlarRememberedMfaDeviceCookieOptions();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.CookieName, Is.EqualTo(AshlarRememberedMfaDeviceCookieDefaults.CookieName));
            Assert.That(options.Cookie.HttpOnly, Is.True);
            Assert.That(options.Cookie.SecurePolicy, Is.EqualTo(CookieSecurePolicy.Always));
            Assert.That(options.Cookie.SameSite, Is.EqualTo(SameSiteMode.Lax));
            Assert.That(options.Cookie.Path, Is.EqualTo("/"));
            Assert.That(options.Cookie.Domain, Is.Null);
        }
    }

    [Test]
    public async Task IssueAsyncCreatesRememberedDeviceAndWritesOnlyRawTokenToCookie()
    {
        var userId = Guid.NewGuid();
        var device = CreateSummary(userId, null);
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new RememberedMfaDeviceCreated(device, "raw-remembered-token")));
        var manager = CreateManager(service.Object);
        var context = CreateContext();

        var result = await manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), mfaResult);

        var setCookie = context.Response.Headers.SetCookie.ToString();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result, Is.EqualTo(device));
            Assert.That(result.ToString(), Does.Not.Contain("raw-remembered-token"));
            Assert.That(setCookie, Does.Contain($"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}=raw-remembered-token"));
            Assert.That(setCookie, Does.Contain("httponly").IgnoreCase);
            Assert.That(setCookie, Does.Contain("secure").IgnoreCase);
            Assert.That(setCookie, Does.Contain("samesite=lax").IgnoreCase);
            Assert.That(setCookie, Does.Contain("path=/").IgnoreCase);
            Assert.That(setCookie, Does.Not.Contain(AshlarSessionAuthenticationDefaults.CookieName));
        }

        service.Verify(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.Is<CreateRememberedMfaDeviceRequest>(r =>
            r.Audit != null &&
            r.Audit.IpAddress == "127.0.0.1" &&
            r.Audit.UserAgent == "unit-test"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task IssueAsyncDoesNotCreateOrExtendSessionCookie()
    {
        var userId = Guid.NewGuid();
        var expiresAt = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);
        var device = CreateSummary(userId, null) with { ExpiresAt = expiresAt };
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new RememberedMfaDeviceCreated(device, "raw-remembered-token")));
        var manager = CreateManager(service.Object);
        var context = CreateContext();
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=existing-session-token";

        await manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), mfaResult);

        var setCookie = context.Response.Headers.SetCookie.ToString();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(setCookie, Does.Contain(AshlarRememberedMfaDeviceCookieDefaults.CookieName));
            Assert.That(setCookie, Does.Not.Contain(AshlarSessionAuthenticationDefaults.CookieName));
            Assert.That(setCookie, Does.Not.Contain("existing-session-token"));
        }
    }

    [Test]
    public void IssueAsyncThrowsWhenServiceRejectsPublicFreshSignalWithoutWritingCookie()
    {
        var userId = Guid.NewGuid();
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<RememberedMfaDeviceCreated>(AshlarFailureCodes.ValidationError));
        var manager = CreateManager(service.Object);
        var context = CreateContext();

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), mfaResult));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Is.Empty);
        }
    }

    [Test]
    public void IssueAsyncUsesDefaultFailureWhenServiceFailsWithoutDetails()
    {
        var userId = Guid.NewGuid();
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<RememberedMfaDeviceCreated>(false));
        var manager = CreateManager(service.Object);
        var context = CreateContext();

        var exception = Assert.ThrowsAsync<AshlarOperationException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), mfaResult));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception!.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(exception.Message, Is.EqualTo("Failed to create remembered MFA device."));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Is.Empty);
        }
    }

    [Test]
    public async Task IssueAsyncPassesTenantAndAuditFromAuthenticationContext()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var device = CreateSummary(userId, tenantId);
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new RememberedMfaDeviceCreated(device, "raw-remembered-token")));
        var manager = CreateManager(service.Object);
        var context = CreateContext();
        var authenticationContext = CreateAuthenticationContext(tenantId);

        await manager.IssueAfterSuccessfulMfaAsync(context, authenticationContext, mfaResult);

        service.Verify(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.Is<CreateRememberedMfaDeviceRequest>(r =>
            r.Tenant != null &&
            r.Tenant.TenantId == tenantId &&
            r.Audit != null &&
            r.Audit.ActorUserId == userId &&
            r.Audit.IpAddress == "127.0.0.1" &&
            r.Audit.UserAgent == "unit-test" &&
            r.Audit.CorrelationId == "corr"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task IssueAsyncAllowsAuthenticationContextWithoutIpAddress()
    {
        var userId = Guid.NewGuid();
        var device = CreateSummary(userId, null);
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new RememberedMfaDeviceCreated(device, "raw-remembered-token")));
        var manager = CreateManager(service.Object);
        var context = new DefaultHttpContext();
        context.Request.Headers.UserAgent = "unit-test";

        await manager.IssueAfterSuccessfulMfaAsync(context, new AuthenticationContext(UserAgent: "unit-test"), mfaResult);

        service.Verify(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.Is<CreateRememberedMfaDeviceRequest>(r =>
            r.Audit != null &&
            r.Audit.IpAddress == null &&
            r.Audit.UserAgent == "unit-test"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task IssueAsyncIgnoresHttpContextUserClaims()
    {
        var userId = Guid.NewGuid();
        var device = CreateSummary(userId, null);
        var mfaResult = CreatePublicFreshMfaSignalOnlyResult(userId);
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.IsAny<CreateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new RememberedMfaDeviceCreated(device, "raw-remembered-token")));
        var manager = CreateManager(service.Object);
        var context = CreateContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "not-a-guid"),
            new Claim(Ashlar.AspNetCore.Authentication.AshlarClaimTypes.TenantId, "not-a-guid")
        ]));

        await manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), mfaResult);

        service.Verify(s => s.CreateAfterSuccessfulMfaAsync(mfaResult, It.Is<CreateRememberedMfaDeviceRequest>(r =>
            r.Tenant == null &&
            r.Audit != null &&
            r.Audit.ActorUserId == userId), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void EnrichContextAddsRememberedTokenWithoutMutatingUnrelatedItems()
    {
        var manager = CreateManager(Mock.Of<IRememberedMfaDeviceService>());
        var context = CreateContext();
        context.Request.Headers.Cookie = $"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}=raw-remembered-token";
        var authenticationContext = new AuthenticationContext(Items: new Dictionary<string, string> { ["other"] = "value" });

        var enriched = manager.EnrichContext(context, authenticationContext);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(enriched, Is.Not.SameAs(authenticationContext));
            Assert.That(authenticationContext.Items, Does.Not.ContainKey(AuthenticationContextItemKeys.RememberedMfaDeviceToken));
            Assert.That(enriched.Items?["other"], Is.EqualTo("value"));
            Assert.That(enriched.Items?[AuthenticationContextItemKeys.RememberedMfaDeviceToken], Is.EqualTo("raw-remembered-token"));
        }
    }

    [Test]
    public void EnrichContextReturnsOriginalContextWhenCookieIsMissing()
    {
        var manager = CreateManager(Mock.Of<IRememberedMfaDeviceService>());
        var httpContext = CreateContext();
        var authenticationContext = new AuthenticationContext();

        var enriched = manager.EnrichContext(httpContext, authenticationContext);

        Assert.That(enriched, Is.SameAs(authenticationContext));
    }

    [Test]
    public void EnrichContextReturnsOriginalContextWhenCookieIsWhitespace()
    {
        var manager = CreateManager(Mock.Of<IRememberedMfaDeviceService>());
        var httpContext = CreateContext();
        httpContext.Features.Set<IRequestCookiesFeature>(new TestRequestCookiesFeature(new TestCookieCollection(new Dictionary<string, string>
        {
            [AshlarRememberedMfaDeviceCookieDefaults.CookieName] = " "
        })));
        var authenticationContext = new AuthenticationContext();

        var enriched = manager.EnrichContext(httpContext, authenticationContext);

        Assert.That(enriched, Is.SameAs(authenticationContext));
    }

    [Test]
    public void ClearDeletesRememberedDeviceCookie()
    {
        var manager = CreateManager(Mock.Of<IRememberedMfaDeviceService>());
        var context = CreateContext();

        manager.Clear(context);

        var setCookie = context.Response.Headers.SetCookie.ToString();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(setCookie, Does.Contain($"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}="));
            Assert.That(setCookie, Does.Contain("expires=Thu, 01 Jan 1970").IgnoreCase);
            Assert.That(setCookie, Does.Not.Contain(AshlarSessionAuthenticationDefaults.CookieName));
        }
    }

    [Test]
    public async Task RevokeCurrentAsyncRevokesValidatedDeviceAndDeletesCookie()
    {
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.RevokeCurrentAsync(It.IsAny<RevokeCurrentRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        var manager = CreateManager(service.Object);
        var context = CreateContext();
        context.Request.Headers.Cookie = $"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}=raw-remembered-token";

        var revoked = await manager.RevokeCurrentAsync(context, userId, tenant, "logout");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.True);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}="));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Not.Contain(AshlarSessionAuthenticationDefaults.CookieName));
        }

        service.Verify(s => s.RevokeCurrentAsync(It.Is<RevokeCurrentRememberedMfaDeviceRequest>(r =>
            r.ActorUserId == userId &&
            r.Token == "raw-remembered-token" &&
            r.Tenant == tenant &&
            r.Reason == "logout" &&
            r.Audit.ActorUserId == userId), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task RevokeCurrentAsyncAllowsHttpContextWithoutRemoteIpAddress()
    {
        var userId = Guid.NewGuid();
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.RevokeCurrentAsync(It.IsAny<RevokeCurrentRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);
        var manager = CreateManager(service.Object);
        var context = new DefaultHttpContext();
        context.Request.Headers.UserAgent = "unit-test";
        context.Request.Headers.Cookie = $"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}=raw-remembered-token";

        var revoked = await manager.RevokeCurrentAsync(context, userId);

        Assert.That(revoked, Is.True);
        service.Verify(s => s.RevokeCurrentAsync(It.Is<RevokeCurrentRememberedMfaDeviceRequest>(r =>
            r.Audit.IpAddress == null &&
            r.Audit.UserAgent == "unit-test"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task RevokeCurrentAsyncClearsInvalidCookieWithoutRevoking()
    {
        var userId = Guid.NewGuid();
        var service = new Mock<IRememberedMfaDeviceService>();
        service
            .Setup(s => s.RevokeCurrentAsync(It.IsAny<RevokeCurrentRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);
        var manager = CreateManager(service.Object);
        var context = CreateContext();
        context.Request.Headers.Cookie = $"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}=bad-token";

        var revoked = await manager.RevokeCurrentAsync(context, userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.False);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}="));
        }

        service.Verify(s => s.RevokeCurrentAsync(It.IsAny<RevokeCurrentRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task RevokeCurrentAsyncClearsMissingCookieWithoutCallingService()
    {
        var userId = Guid.NewGuid();
        var service = new Mock<IRememberedMfaDeviceService>();
        var manager = CreateManager(service.Object);
        var context = CreateContext();

        var revoked = await manager.RevokeCurrentAsync(context, userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.False);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}="));
        }

        service.Verify(s => s.ValidateAsync(It.IsAny<Guid>(), It.IsAny<ValidateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RevokeCurrentAsyncClearsWhitespaceCookieWithoutCallingService()
    {
        var userId = Guid.NewGuid();
        var service = new Mock<IRememberedMfaDeviceService>();
        var manager = CreateManager(service.Object);
        var context = CreateContext();
        context.Features.Set<IRequestCookiesFeature>(new TestRequestCookiesFeature(new TestCookieCollection(new Dictionary<string, string>
        {
            [AshlarRememberedMfaDeviceCookieDefaults.CookieName] = " "
        })));

        var revoked = await manager.RevokeCurrentAsync(context, userId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(revoked, Is.False);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarRememberedMfaDeviceCookieDefaults.CookieName}="));
        }

        service.Verify(s => s.ValidateAsync(It.IsAny<Guid>(), It.IsAny<ValidateRememberedMfaDeviceRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void InvalidInputsAreRejected()
    {
        var manager = CreateManager(Mock.Of<IRememberedMfaDeviceService>());
        var context = CreateContext();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => manager.IssueAfterSuccessfulMfaAsync(null!, CreateAuthenticationContext(), CreatePublicFreshMfaSignalOnlyResult(Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentNullException>(() => manager.IssueAfterSuccessfulMfaAsync(context, null!, CreatePublicFreshMfaSignalOnlyResult(Guid.NewGuid())));
            Assert.ThrowsAsync<ArgumentNullException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), null!));
            Assert.ThrowsAsync<ArgumentException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), new MfaAuthenticationResult(MfaAuthenticationStatus.MfaRequired, Mock.Of<IUser>())));
            Assert.ThrowsAsync<ArgumentException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, FreshMfaSatisfied: true)));
            Assert.ThrowsAsync<ArgumentException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, Mock.Of<IUser>())));
            Assert.ThrowsAsync<ArgumentException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, Mock.Of<IUser>(), FreshMfaSatisfied: true)));
            Assert.ThrowsAsync<ArgumentException>(() => manager.IssueAfterSuccessfulMfaAsync(context, CreateAuthenticationContext(), CreatePublicFreshMfaSignalOnlyResult(Guid.Empty)));
            Assert.Throws<ArgumentNullException>(() => manager.EnrichContext(null!, new AuthenticationContext()));
            Assert.Throws<ArgumentNullException>(() => manager.EnrichContext(context, null!));
            Assert.Throws<ArgumentNullException>(() => manager.Clear(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => manager.RevokeCurrentAsync(null!, Guid.NewGuid()));
            Assert.ThrowsAsync<ArgumentException>(() => manager.RevokeCurrentAsync(context, Guid.Empty));
            Assert.Throws<ArgumentNullException>(() => new AshlarRememberedMfaDeviceCookieManager(null!, Options.Create(new AshlarRememberedMfaDeviceCookieOptions())));
            Assert.Throws<ArgumentNullException>(() => new AshlarRememberedMfaDeviceCookieManager(Mock.Of<IRememberedMfaDeviceService>(), null!));
            Assert.Throws<ArgumentNullException>(() => new AshlarRememberedMfaDeviceCookieManager(Mock.Of<IRememberedMfaDeviceService>(), Mock.Of<IOptions<AshlarRememberedMfaDeviceCookieOptions>>(o => o.Value == null!)));
        }
    }

    private static AshlarRememberedMfaDeviceCookieManager CreateManager(IRememberedMfaDeviceService service)
    {
        return new AshlarRememberedMfaDeviceCookieManager(service, Options.Create(new AshlarRememberedMfaDeviceCookieOptions()));
    }

    private static MfaAuthenticationResult CreatePublicFreshMfaSignalOnlyResult(Guid userId)
    {
        var user = new Mock<IUser>();
        user.SetupGet(u => u.Id).Returns(userId);
        return new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user.Object, FreshMfaSatisfied: true);
    }

    private static AuthenticationContext CreateAuthenticationContext(Guid? tenantId = null)
    {
        return new AuthenticationContext(
            TenantId: tenantId,
            IpAddress: "127.0.0.1",
            UserAgent: "unit-test",
            CorrelationId: "corr");
    }

    private static DefaultHttpContext CreateContext()
    {
        var context = new DefaultHttpContext
        {
            Connection =
            {
                RemoteIpAddress = System.Net.IPAddress.Loopback
            }
        };
        context.Request.Headers.UserAgent = "unit-test";
        return context;
    }

    private static RememberedMfaDeviceSummary CreateSummary(Guid userId, Guid? tenantId)
    {
        var now = DateTimeOffset.UtcNow;
        return new RememberedMfaDeviceSummary(Guid.NewGuid(), userId, tenantId, "laptop", now, null, now.AddDays(30), null, null, true);
    }

    private sealed class TestCookieCollection(IReadOnlyDictionary<string, string> cookies) : IRequestCookieCollection
    {
        public ICollection<string> Keys => cookies.Keys.ToArray();

        public int Count => cookies.Count;

        public string? this[string key] => cookies.TryGetValue(key, out var value) ? value : null;

        public bool ContainsKey(string key)
        {
            return cookies.ContainsKey(key);
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            return cookies.GetEnumerator();
        }

        public bool TryGetValue(string key, out string value)
        {
            if (cookies.TryGetValue(key, out var found))
            {
                value = found;
                return true;
            }

            value = string.Empty;
            return false;
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    private sealed class TestRequestCookiesFeature(IRequestCookieCollection cookies) : IRequestCookiesFeature
    {
        public IRequestCookieCollection Cookies
        {
            get => cookies;
            set => cookies = value;
        }
    }
}

