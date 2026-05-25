using System.Net;
using System.Security.Claims;
using Ashlar.Auditing;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Models.Tenants;
using Ashlar.Security.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarSignInManagerTests
{
    [Test]
    public async Task SignInAsyncShouldAppendSecureHttpOnlyCookie()
    {
        await using var provider = CreateProvider(out _);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        await manager.SignInAsync(context, Guid.NewGuid());

        var setCookie = context.Response.Headers.SetCookie.ToString();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(setCookie, Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token"));
            Assert.That(setCookie, Does.Contain("httponly").IgnoreCase);
            Assert.That(setCookie, Does.Contain("secure").IgnoreCase);
            Assert.That(setCookie, Does.Contain("samesite=lax").IgnoreCase);
            Assert.That(setCookie, Does.Contain("path=/").IgnoreCase);
        }
    }

    [Test]
    public async Task SignInAsyncShouldStoreOnlyTokenHashViaSessionService()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        var session = await manager.SignInAsync(context, Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.CreatedSession, Is.SameAs(session));
            Assert.That(repository.CreatedSession?.TokenHash, Is.EqualTo("hashed:raw-token"));
            Assert.That(repository.CreatedSession?.TokenHash, Is.Not.EqualTo("raw-token"));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain("raw-token"));
        }
    }

    [Test]
    public async Task SignInAsyncShouldAllowHttpContextWithoutRemoteIpAddress()
    {
        await using var provider = CreateProvider(out _);
        var context = new DefaultHttpContext
        {
            RequestServices = provider
        };
        context.Request.Headers.UserAgent = "unit-test";
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        await manager.SignInAsync(context, Guid.NewGuid());

        Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token"));
    }

    [Test]
    public async Task SignInAsyncShouldRevokeExistingSessionIfPresent()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        var firstSession = await manager.SignInAsync(context, Guid.NewGuid());
        context.Response.Headers.Clear();

        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var secondSession = await manager.SignInAsync(context, Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.RevokedSessionId, Is.EqualTo(firstSession.Id));
            Assert.That(repository.RevocationReason, Is.EqualTo("session-replaced"));
            Assert.That(secondSession.Id, Is.Not.EqualTo(firstSession.Id));
            Assert.That(repository.CreatedSession?.Id, Is.EqualTo(secondSession.Id));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain("raw-token"));
        }
    }

    [Test]
    public async Task SignInAsyncShouldRevokeExistingSessionIfPresentInPrincipal()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        var firstSession = await manager.SignInAsync(context, Guid.NewGuid());
        context.Response.Headers.Clear();

        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(AshlarClaimTypes.SessionId, firstSession.Id.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        var secondSession = await manager.SignInAsync(context, Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.RevokedSessionId, Is.EqualTo(firstSession.Id));
            Assert.That(repository.RevocationReason, Is.EqualTo("session-replaced"));
            Assert.That(secondSession.Id, Is.Not.EqualTo(firstSession.Id));
        }
    }

    [Test]
    public async Task SignOutAsyncShouldRevokeCurrentSessionAndDeleteCookie()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();
        var session = await manager.SignInAsync(context, Guid.NewGuid());
        context.Response.Headers.Clear();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(AshlarClaimTypes.SessionId, session.Id.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        await manager.SignOutAsync(context, "user-logout");

        var setCookie = context.Response.Headers.SetCookie.ToString();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.RevokedSessionId, Is.EqualTo(session.Id));
            Assert.That(repository.RevocationReason, Is.EqualTo("user-logout"));
            Assert.That(setCookie, Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}="));
            Assert.That(setCookie, Does.Contain("expires=Thu, 01 Jan 1970").IgnoreCase);
        }
    }

    [Test]
    public async Task SignOutAsyncShouldValidateCookieWhenCurrentPrincipalHasNoSessionClaim()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();
        var session = await manager.SignInAsync(context, Guid.NewGuid());
        context.Response.Headers.Clear();
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        await manager.SignOutAsync(context);

        Assert.That(repository.RevokedSessionId, Is.EqualTo(session.Id));
    }

    [Test]
    public async Task SignOutAsyncShouldDeleteCookieWithoutRevocationWhenCookieValidationHasNoSession()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidateAuthenticationSessionResult.Failed);
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        await manager.SignOutAsync(context);

        using (Assert.EnterMultipleScope())
        {
            sessionService.Verify(s => s.RevokeSessionAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<AuditContext?>(), It.IsAny<CancellationToken>()), Times.Never);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}="));
        }
    }

    [Test]
    public async Task SignOutAsyncShouldDeleteCookieWithoutRevocationWhenCookieValidationSucceedsWithoutSession()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidateAuthenticationSessionResult(
                Succeeded: true,
                Session: null,
                UserId: Guid.NewGuid(),
                Status: AuthenticationSessionValidationStatus.Success));
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        await manager.SignOutAsync(context);

        using (Assert.EnterMultipleScope())
        {
            sessionService.Verify(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()), Times.Once);
            sessionService.Verify(s => s.RevokeSessionAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<AuditContext?>(), It.IsAny<CancellationToken>()), Times.Never);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}="));
        }
    }

    [Test]
    public async Task SignOutAsyncShouldDeleteCookieWhenSessionClaimIsInvalid()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(AshlarClaimTypes.SessionId, "not-a-guid")
            ], AshlarSessionAuthenticationDefaults.AuthenticationScheme))
        };

        await manager.SignOutAsync(context);

        using (Assert.EnterMultipleScope())
        {
            sessionService.Verify(s => s.RevokeSessionAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<AuditContext?>(), It.IsAny<CancellationToken>()), Times.Never);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}="));
        }
    }

    [Test]
    public async Task SignInAndSignOutShouldRespectConfiguredCookieName()
    {
        await using var provider = CreateProvider(out var repository, options => options.CookieName = "Custom.Session");
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        var session = await manager.SignInAsync(context, Guid.NewGuid());
        var signInCookie = context.Response.Headers.SetCookie.ToString();
        context.Response.Headers.Clear();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(AshlarClaimTypes.SessionId, session.Id.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        await manager.SignOutAsync(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(signInCookie, Does.Contain("Custom.Session=raw-token"));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain("Custom.Session="));
            Assert.That(repository.RevokedSessionId, Is.EqualTo(session.Id));
        }
    }

    [Test]
    public async Task SignInShouldRespectConfiguredSchemeName()
    {
        await using var provider = CreateProvider(out _, options =>
        {
            options.SchemeName = "CustomAshlar";
            options.CookieName = "CustomScheme.Session";
        });
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        await manager.SignInAsync(context, Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain("CustomScheme.Session=raw-token"));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Not.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token"));
        }
    }

    [Test]
    public async Task SignInShouldKeepFirstRegisteredSchemeWhenSessionsAreRegisteredTwice()
    {
        var repository = new InMemoryAuthenticationSessionRepository();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAuthenticationSessionRepository>(repository);
        services.AddSingleton<ISecureTokenGenerator>(new FixedSessionTokenGenerator("raw-token"));
        services.AddSingleton<ISecureTokenHasher, PrefixSessionTokenHasher>();
        services.AddAshlarIdentity(configureSessions: sessionOptions =>
        {
            sessionOptions.DefaultLifetime = TimeSpan.FromHours(1);
        });
        services.AddAshlarAspNetCoreSessions(options =>
        {
            options.SchemeName = "FirstAshlar";
            options.CookieName = "First.Session";
        });
        services.AddAshlarAspNetCoreSessions(options =>
        {
            options.SchemeName = "SecondAshlar";
            options.CookieName = "Second.Session";
        });
        await using var provider = services.BuildServiceProvider();
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        await manager.SignInAsync(context, Guid.NewGuid());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain("First.Session=raw-token"));
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Not.Contain("Second.Session=raw-token"));
        }
    }

    [Test]
    public async Task ListSessionsForCurrentUserAsyncShouldThrowWhenNotAuthenticated()
    {
        await using var provider = CreateProvider(out _);
        var context = new DefaultHttpContext { RequestServices = provider };
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.ListSessionsForCurrentUserAsync(context));
    }

    [Test]
    public async Task ListSessionsForCurrentUserAsyncShouldPassClaimsToService()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D")),
            new Claim(AshlarClaimTypes.SessionId, sessionId.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        await manager.ListSessionsForCurrentUserAsync(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.ListUserId, Is.EqualTo(userId));
            Assert.That(repository.ListActiveOnly, Is.True);
        }
    }

    [Test]
    public async Task RevokeSessionForCurrentUserAsyncShouldPassClaimsToService()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();
        var userId = Guid.NewGuid();
        var targetSessionId = Guid.NewGuid();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        await manager.RevokeSessionForCurrentUserAsync(context, targetSessionId, "cleanup");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.RevokedSessionId, Is.EqualTo(targetSessionId));
            Assert.That(repository.RevokedUserId, Is.EqualTo(userId));
            Assert.That(repository.RevocationReason, Is.EqualTo("cleanup"));
        }
    }

    [Test]
    public async Task RevokeSessionForCurrentUserAsyncShouldPassRequestContext()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        sessionService
            .Setup(s => s.RevokeSessionForUserAsync(It.IsAny<Guid>(), It.IsAny<RevokeAuthenticationSessionRequest>(), It.IsAny<CancellationToken>()))
            .Returns(completion.Task);
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext();
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var targetSessionId = Guid.NewGuid();
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10");
        context.Request.Headers.UserAgent = "NUnit";
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D")),
            new Claim(AshlarClaimTypes.TenantId, tenantId.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        var revokeTask = manager.RevokeSessionForCurrentUserAsync(context, targetSessionId);
        Assert.That(revokeTask.IsCompleted, Is.False);
        completion.SetResult(true);
        Assert.That(await revokeTask, Is.True);

        sessionService.Verify(s => s.RevokeSessionForUserAsync(userId, It.Is<RevokeAuthenticationSessionRequest>(r =>
            r.SessionId == targetSessionId &&
            r.Tenant != null &&
            r.Tenant.TenantId == tenantId &&
            r.Audit != null &&
            r.Audit.ActorUserId == userId &&
            r.Audit.IpAddress == "203.0.113.10" &&
            r.Audit.UserAgent == "NUnit"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void RevokeSessionForCurrentUserAsyncShouldPropagateServiceFailure()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.RevokeSessionForUserAsync(It.IsAny<Guid>(), It.IsAny<RevokeAuthenticationSessionRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("revoke failed"));
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString("D"))
            ], AshlarSessionAuthenticationDefaults.AuthenticationScheme))
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeSessionForCurrentUserAsync(context, Guid.NewGuid()));
    }

    [Test]
    public async Task RevokeSessionForCurrentUserAsyncShouldThrowWhenNotAuthenticated()
    {
        await using var provider = CreateProvider(out _);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeSessionForCurrentUserAsync(context, Guid.NewGuid()));
    }

    [Test]
    public async Task RevokeOtherSessionsForCurrentUserAsyncShouldPassClaimsToService()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D")),
            new Claim(AshlarClaimTypes.SessionId, currentSessionId.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        await manager.RevokeOtherSessionsForCurrentUserAsync(context, "security-sweep");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.RevokedUserId, Is.EqualTo(userId));
            Assert.That(repository.ExcludedSessionId, Is.EqualTo(currentSessionId));
            Assert.That(repository.RevocationReason, Is.EqualTo("security-sweep"));
        }
    }

    [Test]
    public async Task RevokeOtherSessionsForCurrentUserAsyncShouldPassRequestContext()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        sessionService
            .Setup(s => s.RevokeOtherSessionsAsync(It.IsAny<Guid>(), It.IsAny<RevokeOtherAuthenticationSessionsRequest>(), It.IsAny<CancellationToken>()))
            .Returns(completion.Task);
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext();
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.11");
        context.Request.Headers.UserAgent = "NUnit";
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D")),
            new Claim(AshlarClaimTypes.SessionId, currentSessionId.ToString("D")),
            new Claim(AshlarClaimTypes.TenantId, tenantId.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        var revokeTask = manager.RevokeOtherSessionsForCurrentUserAsync(context);
        Assert.That(revokeTask.IsCompleted, Is.False);
        completion.SetResult(1);
        Assert.That(await revokeTask, Is.EqualTo(1));

        sessionService.Verify(s => s.RevokeOtherSessionsAsync(userId, It.Is<RevokeOtherAuthenticationSessionsRequest>(r =>
            r.CurrentSessionId == currentSessionId &&
            r.Tenant != null &&
            r.Tenant.TenantId == tenantId &&
            r.Audit != null &&
            r.Audit.ActorUserId == userId &&
            r.Audit.IpAddress == "203.0.113.11" &&
            r.Audit.UserAgent == "NUnit"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void RevokeOtherSessionsForCurrentUserAsyncShouldPropagateServiceFailure()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.RevokeOtherSessionsAsync(It.IsAny<Guid>(), It.IsAny<RevokeOtherAuthenticationSessionsRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("revoke failed"));
        var manager = new AshlarSignInManager(
            sessionService.Object,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString("D")),
                new Claim(AshlarClaimTypes.SessionId, Guid.NewGuid().ToString("D"))
            ], AshlarSessionAuthenticationDefaults.AuthenticationScheme))
        };

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(context));
    }

    [Test]
    public async Task RevokeOtherSessionsForCurrentUserAsyncShouldThrowWhenNotAuthenticated()
    {
        await using var provider = CreateProvider(out _);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(context));
    }

    [Test]
    public async Task RevokeOtherSessionsForCurrentUserAsyncShouldThrowWhenNoSessionClaim()
    {
        await using var provider = CreateProvider(out _);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(context));
    }

    [Test]
    public void ConstructorShouldThrowOnNullSessionService()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullOptionsMonitor()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            Mock.Of<IAuthenticationSessionService>(),
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!,
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullRegistration()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            Mock.Of<IAuthenticationSessionService>(),
            CreateOptionsMonitor(),
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!));
    }

    private static ServiceProvider CreateProvider(
        out InMemoryAuthenticationSessionRepository repository,
        Action<AshlarSessionAuthenticationOptions>? configure = null)
    {
        repository = new InMemoryAuthenticationSessionRepository();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAuthenticationSessionRepository>(repository);
        services.AddSingleton<ISecureTokenGenerator>(new FixedSessionTokenGenerator("raw-token"));
        services.AddSingleton<ISecureTokenHasher, PrefixSessionTokenHasher>();
        services.AddAshlarIdentity(configureSessions: sessionOptions =>
        {
            sessionOptions.DefaultLifetime = TimeSpan.FromHours(1);
        });
        services.AddAshlarAspNetCoreSessions(configure);
        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext CreateContext(IServiceProvider provider)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = provider,
            Connection =
            {
                RemoteIpAddress = IPAddress.Loopback
            }
        };
        context.Request.Headers.UserAgent = "unit-test";
        return context;
    }

    private static IOptionsMonitor<AshlarSessionAuthenticationOptions> CreateOptionsMonitor()
    {
        var options = new AshlarSessionAuthenticationOptions();
        var monitor = new Mock<IOptionsMonitor<AshlarSessionAuthenticationOptions>>();
        monitor
            .Setup(m => m.Get(AshlarSessionAuthenticationDefaults.AuthenticationScheme))
            .Returns(options);
        return monitor.Object;
    }

    private sealed class FixedSessionTokenGenerator(string token) : ISecureTokenGenerator
    {
        public string GenerateToken(int byteLength = ISecureTokenGenerator.DefaultByteLength)
        {
            return token;
        }
    }

    private sealed class PrefixSessionTokenHasher : ISecureTokenHasher
    {
        public string HashToken(string token)
        {
            return $"hashed:{token}";
        }
    }

    private sealed class InMemoryAuthenticationSessionRepository : IAuthenticationSessionRepository
    {
        private AuthenticationSession? _session;

        public AuthenticationSession? CreatedSession => _session;
        public Guid? RevokedSessionId { get; private set; }
        public Guid? RevokedUserId { get; private set; }
        public Guid? ExcludedSessionId { get; private set; }
        public string? RevocationReason { get; private set; }
        public Guid? ListUserId { get; private set; }
        public bool? ListActiveOnly { get; private set; }

        public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default)
        {
            _session = session;
            return Task.CompletedTask;
        }

        public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_session?.TokenHash == tokenHash ? _session : null);
        }

        public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_session?.Id == sessionId ? _session : null);
        }

        public Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default)
        {
            if (_session?.Id != sessionId)
            {
                return Task.FromResult(false);
            }

            _session.LastSeenAt = lastSeenAt;
            return Task.FromResult(true);
        }

        public Task<AuthenticationSession?> MarkStepUpVerifiedAsync(Guid sessionId, Guid userId, DateTimeOffset verifiedAt, AuthenticationProviderKey verifiedProvider, string verifiedFactor, CancellationToken cancellationToken = default)
        {
            if (_session?.Id != sessionId || _session.UserId != userId || !_session.IsActive(verifiedAt))
            {
                return Task.FromResult<AuthenticationSession?>(null);
            }

            _session.AdditionalVerificationAt = verifiedAt;
            _session.AdditionalVerificationProvider = verifiedProvider;
            _session.AdditionalVerificationFactor = verifiedFactor;
            return Task.FromResult<AuthenticationSession?>(_session);
        }

        public Task<bool> RevokeSessionAsync(Guid sessionId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            if (_session?.Id != sessionId || _session.RevokedAt != null)
            {
                return Task.FromResult(false);
            }

            _session.RevokedAt = revokedAt;
            _session.RevocationReason = reason;
            RevokedSessionId = sessionId;
            RevocationReason = reason;
            return Task.FromResult(true);
        }

        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            RevokedUserId = userId;
            RevocationReason = reason;
            return Task.FromResult(1);
        }

        public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            ListUserId = userId;
            ListActiveOnly = activeOnly;
            return Task.FromResult((IReadOnlyList<AuthenticationSession>)new List<AuthenticationSession>().AsReadOnly());
        }

        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            RevokedSessionId = sessionId;
            RevokedUserId = userId;
            RevocationReason = reason;
            return Task.FromResult(true);
        }

        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, CancellationToken cancellationToken = default)
        {
            RevokedUserId = userId;
            ExcludedSessionId = excludedSessionId;
            RevocationReason = reason;
            return Task.FromResult(1);
        }
    }
}
