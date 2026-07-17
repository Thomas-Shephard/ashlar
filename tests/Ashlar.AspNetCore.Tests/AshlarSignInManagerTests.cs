using System.Net;
using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Abstractions.Tenancy;
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

        await manager.SignInAsync(context, CreateAuthResult());

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

        var session = await manager.SignInAsync(context, CreateAuthResult());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(session.Id, Is.EqualTo(repository.CreatedSession?.Id));
            Assert.That(repository.CreatedSession?.TokenHash, Is.EqualTo("hashed:raw-token"));
            Assert.That(repository.CreatedSession?.TokenHash, Is.Not.EqualTo("raw-token"));
            Assert.That(session.GetType().GetProperty("TokenHash"), Is.Null);
            Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain("raw-token"));
        }
    }

    [Test]
    public async Task SignInAsyncShouldCreateOrdinarySessionWithoutFreshMfaMetadata()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        await manager.SignInAsync(context, CreateAuthResult(), new CreateAuthenticationSessionRequest(PrimaryProvider: AuthenticationProviderKey.Passkey));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.CreatedSession?.PrimaryProvider, Is.EqualTo(AuthenticationProviderKey.Passkey));
            Assert.That(repository.CreatedSession?.AdditionalVerificationAt, Is.Null);
            Assert.That(repository.CreatedSession?.AdditionalVerificationProvider, Is.Null);
            Assert.That(repository.CreatedSession?.AdditionalVerificationFactor, Is.Null);
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

        await manager.SignInAsync(context, CreateAuthResult());

        Assert.That(context.Response.Headers.SetCookie.ToString(), Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token"));
    }

    [Test]
    public async Task SignInAsyncShouldRevokeExistingSessionIfPresent()
    {
        await using var provider = CreateProvider(out var repository);
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        var firstSession = await manager.SignInAsync(context, CreateAuthResult(), new CreateAuthenticationSessionRequest(TenantId: Guid.NewGuid()));
        context.Response.Headers.Clear();
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var secondSession = await manager.SignInAsync(context, CreateAuthResult());

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

        var firstSession = await manager.SignInAsync(context, CreateAuthResult());
        context.Response.Headers.Clear();
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, firstSession.UserId.ToString("D")),
            new Claim(AshlarClaimTypes.SessionId, firstSession.Id.ToString("D")),
            new Claim(AshlarClaimTypes.TenantId, Guid.NewGuid().ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme));

        var secondSession = await manager.SignInAsync(context, CreateAuthResult());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(repository.RevokedSessionId, Is.EqualTo(firstSession.Id));
            Assert.That(repository.RevocationReason, Is.EqualTo("session-replaced"));
            Assert.That(secondSession.Id, Is.Not.EqualTo(firstSession.Id));
        }
    }

    [Test]
    public async Task SignInAndSignOutShouldRespectConfiguredCookieName()
    {
        await using var provider = CreateProvider(out var repository, options => options.CookieName = "Custom.Session");
        var context = CreateContext(provider);
        var manager = provider.GetRequiredService<IAshlarSignInManager>();

        var session = await manager.SignInAsync(context, CreateAuthResult());
        var signInCookie = context.Response.Headers.SetCookie.ToString();
        context.Response.Headers.Clear();
        context.Request.Headers.Cookie = "Custom.Session=raw-token";
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, session.UserId.ToString("D")),
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

        await manager.SignInAsync(context, CreateAuthResult());

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
        services.AddAshlarProviderScoped<IAuthenticationSessionRepository>(_ => repository);
        services.AddAshlarProviderScoped<IUserRepository>(_ => new InMemoryUserRepository());
        services.AddSingleton<ISecureTokenGenerator>(new FixedSessionTokenGenerator("raw-token"));
        services.AddSingleton<ISecureTokenHasher, PrefixSessionTokenHasher>();
        services.AddAshlarIdentity(configureSessions: sessionOptions =>
        {
            sessionOptions.DefaultLifetime = TimeSpan.FromHours(1);
        });
        services.AddSingleton<IAuthenticationSessionService>(new TestAuthenticationSessionService(repository));
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

        await manager.SignInAsync(context, CreateAuthResult());

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
    public async Task RevokeSessionForCurrentUserAsyncShouldPassActorBoundRequest()
    {
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var targetSessionId = Guid.NewGuid();
        var proof = CreateFreshProof(userId, currentSessionId);
        var service = new Mock<IAuthenticationSessionService>();
        service.Setup(s => s.RevokeSessionForCurrentUserAsync(It.IsAny<RevokeOwnAuthenticationSessionRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var manager = new AshlarSignInManager(service.Object, Mock.Of<IAuthenticationSessionReader>(), CreateOptionsMonitor(), new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = CreateAuthenticatedContext(userId, currentSessionId);

        Assert.That(await manager.RevokeSessionForCurrentUserAsync(context, targetSessionId, proof, "cleanup"), Is.True);

        service.Verify(s => s.RevokeSessionForCurrentUserAsync(It.Is<RevokeOwnAuthenticationSessionRequest>(r =>
            r.ActorUserId == userId && r.CurrentSessionId == currentSessionId && r.SessionId == targetSessionId &&
            r.Audit.ActorUserId == userId && r.ActorTenant.TenantId == null && r.FreshMfaProof == proof && r.Reason == "cleanup"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task SignOutAsyncShouldAcceptGlobalPrincipalWithoutCookie()
    {
        var service = new Mock<IAuthenticationSessionService>();
        var manager = new AshlarSignInManager(service.Object, Mock.Of<IAuthenticationSessionReader>(), CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = CreateAuthenticatedContext(Guid.NewGuid(), Guid.NewGuid());

        await manager.SignOutAsync(context);

        service.Verify(s => s.RevokeCurrentSessionAsync(It.IsAny<RevokeCurrentAuthenticationSessionRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public void CurrentUserOperationsShouldRejectInvalidTenantClaim()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var manager = new AshlarSignInManager(Mock.Of<IAuthenticationSessionService>(), Mock.Of<IAuthenticationSessionReader>(), CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = CreateAuthenticatedContext(userId, sessionId);
        ((ClaimsIdentity)context.User.Identity!).AddClaim(new Claim(AshlarClaimTypes.TenantId, "not-a-guid"));

        Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(
            context, CreateFreshProof(userId, sessionId)));
    }

    [Test]
    public void CurrentUserRevocationOperationsShouldRejectMissingContext()
    {
        var manager = new AshlarSignInManager(Mock.Of<IAuthenticationSessionService>(), Mock.Of<IAuthenticationSessionReader>(), CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = new DefaultHttpContext();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => manager.RevokeSessionForCurrentUserAsync(context, Guid.NewGuid(), null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(context, null!));
            Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeSessionForCurrentUserAsync(context, Guid.NewGuid(),
                CreateFreshProof(Guid.NewGuid(), Guid.NewGuid())));
            Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(context,
                CreateFreshProof(Guid.NewGuid(), Guid.NewGuid())));
        }

        var userId = Guid.NewGuid();
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString("D"))],
            AshlarSessionAuthenticationDefaults.AuthenticationScheme));
        var proof = CreateFreshProof(userId, Guid.NewGuid());
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeSessionForCurrentUserAsync(context, Guid.NewGuid(), proof));
            Assert.ThrowsAsync<InvalidOperationException>(() => manager.RevokeOtherSessionsForCurrentUserAsync(context, proof));
        }
    }

    [Test]
    public async Task SignOutAsyncShouldIgnoreInvalidTenantPrincipalWithoutCookie()
    {
        var service = new Mock<IAuthenticationSessionService>();
        var manager = new AshlarSignInManager(service.Object, Mock.Of<IAuthenticationSessionReader>(), CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = CreateAuthenticatedContext(Guid.NewGuid(), Guid.NewGuid());
        ((ClaimsIdentity)context.User.Identity!).AddClaim(new Claim(AshlarClaimTypes.TenantId, "invalid"));

        await manager.SignOutAsync(context);

        service.VerifyNoOtherCalls();
    }

    [Test]
    public async Task RevokeOtherSessionsForCurrentUserAsyncShouldPassActorBoundRequest()
    {
        var userId = Guid.NewGuid();
        var currentSessionId = Guid.NewGuid();
        var proof = CreateFreshProof(userId, currentSessionId);
        var service = new Mock<IAuthenticationSessionService>();
        service.Setup(s => s.RevokeOtherSessionsForCurrentUserAsync(It.IsAny<RevokeOwnOtherAuthenticationSessionsRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(2);
        var manager = new AshlarSignInManager(service.Object, Mock.Of<IAuthenticationSessionReader>(), CreateOptionsMonitor(), new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme });
        var context = CreateAuthenticatedContext(userId, currentSessionId);

        Assert.That(await manager.RevokeOtherSessionsForCurrentUserAsync(context, proof, "cleanup"), Is.EqualTo(2));

        service.Verify(s => s.RevokeOtherSessionsForCurrentUserAsync(It.Is<RevokeOwnOtherAuthenticationSessionsRequest>(r =>
            r.ActorUserId == userId && r.CurrentSessionId == currentSessionId && r.Audit.ActorUserId == userId &&
            r.ActorTenant.TenantId == null && r.FreshMfaProof == proof && r.Reason == "cleanup"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void ConstructorShouldThrowOnNullSessionService()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            null!,
            Mock.Of<IAuthenticationSessionReader>(),
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullSessionReader()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            Mock.Of<IAuthenticationSessionService>(),
            null!,
            CreateOptionsMonitor(),
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullOptionsMonitor()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            Mock.Of<IAuthenticationSessionService>(),
            Mock.Of<IAuthenticationSessionReader>(),
            null!,
            new AshlarSessionRegistration { SchemeName = AshlarSessionAuthenticationDefaults.AuthenticationScheme }));
    }

    [Test]
    public void ConstructorShouldThrowOnNullRegistration()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSignInManager(
            Mock.Of<IAuthenticationSessionService>(),
            Mock.Of<IAuthenticationSessionReader>(),
            CreateOptionsMonitor(),
            null!));
    }

    private static ServiceProvider CreateProvider(
        out InMemoryAuthenticationSessionRepository repository,
        Action<AshlarSessionAuthenticationOptions>? configure = null)
    {
        var sessionRepository = new InMemoryAuthenticationSessionRepository();
        repository = sessionRepository;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarProviderScoped<IAuthenticationSessionRepository>(_ => sessionRepository);
        services.AddAshlarProviderScoped<IUserRepository>(_ => new InMemoryUserRepository());
        services.AddSingleton<ISecureTokenGenerator>(new FixedSessionTokenGenerator("raw-token"));
        services.AddSingleton<ISecureTokenHasher, PrefixSessionTokenHasher>();
        services.AddAshlarIdentity(configureSessions: sessionOptions =>
        {
            sessionOptions.DefaultLifetime = TimeSpan.FromHours(1);
        });
        services.AddSingleton<IAuthenticationSessionService>(new TestAuthenticationSessionService(sessionRepository));
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

    private static MfaAuthenticationResult CreateAuthResult()
    {
        var user = new Mock<IUser>();
        user.SetupGet(u => u.Id).Returns(Guid.NewGuid());
        user.SetupGet(u => u.DisplayEmail).Returns("user@example.com");
        return new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user.Object);
    }

    private static AuthenticationSession CreateSession(Guid sessionId, out Guid userId, out Guid tenantId)
    {
        userId = Guid.NewGuid();
        tenantId = Guid.NewGuid();
        return new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = tenantId,
            TokenHash = "hashed:raw-token",
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
        };
    }

    private static CreatedAuthenticationSession CreateCreatedSession(AuthenticationSession session)
    {
        return new CreatedAuthenticationSession(
            session.Id,
            session.UserId,
            session.TenantId,
            session.CreatedAt,
            session.AuthenticatedAt,
            session.PrimaryProvider,
            session.ExpiresAt,
            session.IpAddress,
            session.UserAgent,
            session.Metadata);
    }

    private static DefaultHttpContext CreateAuthenticatedContext(Guid userId, Guid sessionId) => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D")),
            new Claim(AshlarClaimTypes.SessionId, sessionId.ToString("D"))
        ], AshlarSessionAuthenticationDefaults.AuthenticationScheme))
    };

    private static FreshMfaVerificationProof CreateFreshProof(Guid userId, Guid sessionId)
    {
        var now = DateTimeOffset.UtcNow;
        var session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = now,
            AuthenticatedAt = now,
            AdditionalVerificationAt = now,
            AdditionalVerificationFactor = "totp",
            ExpiresAt = now.AddHours(1)
        };
        var validatedSession = (ValidatedAuthenticationSession)Activator.CreateInstance(typeof(ValidatedAuthenticationSession),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic, null, [session], null)!;
        var result = new StepUpAuthenticationService().CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.FromMinutes(5)));
        return result.Value!;
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

    private sealed class TestAuthenticationSessionService(InMemoryAuthenticationSessionRepository repository) : IAuthenticationSessionService
    {
        private const string RawToken = "raw-token";
        private static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);

        public async Task<CreateAuthenticationSessionResult> CreateSessionAsync(MfaAuthenticationResult authenticationResult, CreateAuthenticationSessionRequest request, CancellationToken cancellationToken = default)
        {
            if (authenticationResult.User == null)
            {
                throw new InvalidOperationException("Test sign-in requires a user.");
            }

            var now = DateTimeOffset.UtcNow;
            var session = new AuthenticationSession
            {
                Id = Guid.NewGuid(),
                UserId = authenticationResult.User.Id,
                TenantId = request.TenantId,
                TokenHash = $"hashed:{RawToken}",
                CreatedAt = now,
                AuthenticatedAt = request.AuthenticatedAt,
                PrimaryProvider = request.PrimaryProvider,
                ExpiresAt = now.Add(request.Lifetime ?? Lifetime),
                IpAddress = request.IpAddress,
                UserAgent = request.UserAgent,
                Metadata = request.Metadata
            };
            await repository.CreateSessionAsync(session, cancellationToken);
            return new CreateAuthenticationSessionResult(RawToken, CreateCreatedSession(session));
        }

        public Task<ValidateAuthenticationSessionResult> ValidateSessionAsync(string? token, CancellationToken cancellationToken = default)
        {
            return token == RawToken && repository.CreatedSession is { } session
                ? Task.FromResult(new ValidateAuthenticationSessionResult(true, session, session.UserId, AuthenticationSessionValidationStatus.Succeeded))
                : Task.FromResult(ValidateAuthenticationSessionResult.Failed);
        }

        public Task<Result<AuthenticationSession>> MarkStepUpVerifiedAsync(MfaAuthenticationResult authenticationResult, MarkSessionStepUpVerifiedRequest request, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result.Failure<AuthenticationSession>(AshlarFailureCodes.StepUpRequired));
        }

        public async Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(Guid userId, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default)
        {
            var sessions = await repository.ListSessionsForUserAsync(userId, request.ActiveOnly, DateTimeOffset.UtcNow, cancellationToken);
            return sessions.Select(session => new AuthenticationSessionSummary
            {
                Id = session.Id,
                CreatedAt = session.CreatedAt,
                ExpiresAt = session.ExpiresAt,
                LastSeenAt = session.LastSeenAt,
                RevokedAt = session.RevokedAt,
                RevocationReason = session.RevocationReason,
                IpAddress = session.IpAddress,
                UserAgent = session.UserAgent,
                Metadata = session.Metadata,
                IsCurrent = request.CurrentSessionId == session.Id,
                IsActive = session.IsActive(DateTimeOffset.UtcNow)
            }).ToArray();
        }

        public Task<bool> RevokeSessionForCurrentUserAsync(RevokeOwnAuthenticationSessionRequest request, CancellationToken cancellationToken = default)
        {
            return repository.RevokeSessionByIdAsync(request.SessionId, request.ActorUserId, DateTimeOffset.UtcNow, request.Reason, request.ActorTenant, false, cancellationToken);
        }

        public Task<int> RevokeOtherSessionsForCurrentUserAsync(RevokeOwnOtherAuthenticationSessionsRequest request, CancellationToken cancellationToken = default)
        {
            return repository.RevokeOtherSessionsForUserAsync(request.ActorUserId, request.CurrentSessionId, DateTimeOffset.UtcNow, request.Reason, request.ActorTenant, false, cancellationToken);
        }

        public async Task<bool> RevokeCurrentSessionAsync(RevokeCurrentAuthenticationSessionRequest request, CancellationToken cancellationToken = default)
        {
            var validation = await ValidateSessionAsync(request.Token, cancellationToken);
            return validation.Session != null && await repository.RevokeSessionByIdAsync(validation.Session.Id, validation.Session.UserId,
                DateTimeOffset.UtcNow, request.Reason, validation.Session.TenantId is { } tenantId ? new TenantContext(tenantId) : TenantContext.Global,
                false, cancellationToken);
        }

        public Task<bool> RevokeIssuedSessionAsync(RevokeIssuedAuthenticationSessionRequest request, CancellationToken cancellationToken = default)
        {
            return repository.RevokeSessionByIdAsync(request.Session.Id, request.Session.UserId, DateTimeOffset.UtcNow, request.Reason,
                request.Session.TenantId is { } tenantId ? new TenantContext(tenantId) : TenantContext.Global,
                false, cancellationToken);
        }
    }

    private sealed class InMemoryUserRepository : IUserRepository
    {
        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(null);
        }

        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(new AshlarUser
            {
                Id = userId,
                DisplayEmail = $"{userId:N}@example.com",
                AccountState = UserAccountState.Active
            });
        }

        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IUser?>(null);
        }

        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
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

        public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default)
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

        public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, bool includeAllTenants = false, CancellationToken cancellationToken = default)
        {
            RevokedSessionId = sessionId;
            RevokedUserId = userId;
            RevocationReason = reason;
            return Task.FromResult(true);
        }

        public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason = null, TenantContext? tenant = null, bool includeAllTenants = false, CancellationToken cancellationToken = default)
        {
            RevokedUserId = userId;
            ExcludedSessionId = excludedSessionId;
            RevocationReason = reason;
            return Task.FromResult(1);
        }
    }
}
