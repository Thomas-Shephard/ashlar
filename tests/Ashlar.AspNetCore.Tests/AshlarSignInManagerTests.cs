using System.Net;
using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.AspNetCore.Tests;

public sealed class AshlarSignInManagerTests
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
            sessionService.Verify(s => s.RevokeSessionAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
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
            sessionService.Verify(s => s.RevokeSessionAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
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
            sessionService.Verify(s => s.RevokeSessionAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
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
        public string? RevocationReason { get; private set; }

        public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default)
        {
            _session = session;
            return Task.CompletedTask;
        }

        public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_session?.TokenHash == tokenHash ? _session : null);
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

        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason = null, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
