using System.Net;
using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Ashlar.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarSessionAuthenticationHandlerTests
{
    [Test]
    public async Task AuthenticateAsyncShouldReturnNoResultWhenCookieIsMissing()
    {
        await using var provider = CreateProvider(Mock.Of<IAuthenticationSessionService>());
        var context = CreateContext(provider);

        var result = await AuthenticateAsync(provider, context);

        Assert.That(result.None, Is.True);
    }

    [Test]
    public async Task AuthenticateAsyncShouldCreateExpectedClaimsForValidCookie()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var session = CreateSession(sessionId, userId, DateTimeOffset.UtcNow.AddHours(1), tenantId);
        session.AuthenticatedAt = new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
        session.PrimaryProvider = AuthenticationProviderKey.EmailCode;
        session.AdditionalVerificationAt = new DateTimeOffset(2026, 5, 17, 12, 5, 0, TimeSpan.Zero);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, "totp");
        session.AdditionalVerificationFactor = "totp";
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSuccessfulValidation(session));
        await using var provider = CreateProvider(sessionService.Object);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(context.Items[AshlarHttpContextItems.ValidatedAuthenticationSession], Is.TypeOf<ValidatedAuthenticationSession>());
            Assert.That(result.Principal?.FindFirstValue(ClaimTypes.NameIdentifier), Is.EqualTo(userId.ToString("D")));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.SessionId), Is.EqualTo(sessionId.ToString("D")));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.TenantId), Is.EqualTo(tenantId.ToString("D")));
            Assert.That(result.Principal?.FindFirstValue(ClaimTypes.AuthenticationMethod), Is.EqualTo(AshlarSessionAuthenticationDefaults.AuthenticationScheme));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.AuthenticatedAt), Is.EqualTo(session.AuthenticatedAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.PrimaryProviderType), Is.EqualTo(ProviderType.EmailCode.Value));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.PrimaryProviderName), Is.EqualTo(AuthenticationProviderKey.EmailCode.Name));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.AdditionalVerificationAt), Is.EqualTo(session.AdditionalVerificationAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.AdditionalVerificationProviderType), Is.EqualTo(ProviderType.Mfa.Value));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.AdditionalVerificationProviderName), Is.EqualTo("totp"));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.AdditionalVerificationFactor), Is.EqualTo("totp"));
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldUseValidatedCapabilityWhenRawResultDisagrees()
    {
        var validatedSession = CreateSession(Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        var rawSession = CreateSession(Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService.Setup(service => service.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSuccessfulValidation(rawSession, validatedSession));
        await using var provider = CreateProvider(sessionService.Object);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Principal?.FindFirstValue(ClaimTypes.NameIdentifier), Is.EqualTo(validatedSession.UserId.ToString("D")));
            Assert.That(result.Principal?.FindFirstValue(AshlarClaimTypes.SessionId), Is.EqualTo(validatedSession.Id.ToString("D")));
            Assert.That(context.Items.Values, Has.None.TypeOf<AuthenticationSession>());
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldFailForExpiredSession()
    {
        var userId = Guid.NewGuid();
        var session = CreateSession(Guid.NewGuid(), userId, DateTimeOffset.UtcNow.AddMinutes(-1));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidateAuthenticationSessionResult.Expired);
        await using var provider = CreateProvider(sessionService.Object);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Failure, Is.Not.Null);
            Assert.That(result.Failure?.Message, Is.EqualTo("Ashlar session validation failed."));
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldDeleteCookieWhenSessionValidationFails()
    {
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidateAuthenticationSessionResult.Failed);
        await using var provider = CreateProvider(sessionService.Object);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context);

        var setCookie = context.Response.Headers.SetCookie.ToString();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(setCookie, Does.Contain($"{AshlarSessionAuthenticationDefaults.CookieName}="));
            Assert.That(setCookie, Does.Contain("expires=Thu, 01 Jan 1970").IgnoreCase);
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldFailForRevokedSession()
    {
        var userId = Guid.NewGuid();
        var session = CreateSession(Guid.NewGuid(), userId, DateTimeOffset.UtcNow.AddHours(1));
        session.RevokedAt = DateTimeOffset.UtcNow;
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidateAuthenticationSessionResult.Revoked);
        await using var provider = CreateProvider(sessionService.Object);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Failure, Is.Not.Null);
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldRespectConfiguredCookieName()
    {
        var userId = Guid.NewGuid();
        var session = CreateSession(Guid.NewGuid(), userId, DateTimeOffset.UtcNow.AddHours(1));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSuccessfulValidation(session));
        await using var provider = CreateProvider(sessionService.Object, options => options.CookieName = "Custom.Session");
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = "Custom.Session=raw-token";

        var result = await AuthenticateAsync(provider, context);

        Assert.That(result.Succeeded, Is.True);
    }

    [Test]
    public async Task AuthenticateAsyncShouldRejectCustomValidationWithoutProofCapability()
    {
        var session = CreateSession(Guid.NewGuid(), Guid.NewGuid(), DateTimeOffset.UtcNow.AddHours(1));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService.Setup(service => service.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(ValidateAuthenticationSessionResult.Failed);
        await using var provider = CreateProvider(sessionService.Object);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(context.Items.ContainsKey(AshlarHttpContextItems.ValidatedAuthenticationSession), Is.False);
        }
    }

    [Test]
    public async Task AuthenticateAsyncShouldRespectConfiguredSchemeName()
    {
        const string scheme = "CustomAshlar";
        var userId = Guid.NewGuid();
        var session = CreateSession(Guid.NewGuid(), userId, DateTimeOffset.UtcNow.AddHours(1));
        var sessionService = new Mock<IAuthenticationSessionService>();
        sessionService
            .Setup(s => s.ValidateSessionAsync("raw-token", It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSuccessfulValidation(session));
        await using var provider = CreateProvider(sessionService.Object, options => options.SchemeName = scheme);
        var context = CreateContext(provider);
        context.Request.Headers.Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}=raw-token";

        var result = await AuthenticateAsync(provider, context, scheme);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Principal?.Identity?.AuthenticationType, Is.EqualTo(scheme));
            Assert.That(result.Principal?.FindFirstValue(ClaimTypes.AuthenticationMethod), Is.EqualTo(scheme));
        }
    }

    [Test]
    public async Task ChallengeAsyncShouldAppendReturnUrlToLoginRedirect()
    {
        await using var provider = CreateProvider(
            Mock.Of<IAuthenticationSessionService>(),
            options => options.LoginPath = "/login");
        var context = CreateContext(provider);

        await provider.GetRequiredService<IAuthenticationService>().ChallengeAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "/protected/resource?tab=settings" });

        Assert.That(
            context.Response.Headers.Location.ToString(),
            Is.EqualTo("http://localhost/login?ReturnUrl=%2Fprotected%2Fresource%3Ftab%3Dsettings"));
    }

    [Test]
    public async Task ChallengeAsyncShouldRedirectToLoginWithoutReturnUrlWhenRedirectUriIsMissing()
    {
        await using var provider = CreateProvider(
            Mock.Of<IAuthenticationSessionService>(),
            options => options.LoginPath = "/login");
        var context = CreateContext(provider);

        await provider.GetRequiredService<IAuthenticationService>().ChallengeAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties());

        Assert.That(context.Response.Headers.Location.ToString(), Is.EqualTo("http://localhost/login"));
    }

    [Test]
    public async Task ChallengeAsyncShouldUseBaseBehaviorWhenLoginPathIsMissing()
    {
        await using var provider = CreateProvider(Mock.Of<IAuthenticationSessionService>());
        var context = CreateContext(provider);

        await provider.GetRequiredService<IAuthenticationService>().ChallengeAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties());

        Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status401Unauthorized));
    }

    [Test]
    public async Task ChallengeAsyncShouldReturnUnauthorizedForApiRequests()
    {
        await using var provider = CreateProvider(
            Mock.Of<IAuthenticationSessionService>(),
            options => options.LoginPath = "/login");
        var context = CreateContext(provider);
        context.Request.Headers.Accept = "application/json";

        await provider.GetRequiredService<IAuthenticationService>().ChallengeAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "/protected/resource" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status401Unauthorized));
            Assert.That(context.Response.Headers.Location.ToString(), Is.Empty);
        }
    }

    [Test]
    public async Task ForbidAsyncShouldAppendReturnUrlToAccessDeniedRedirect()
    {
        await using var provider = CreateProvider(
            Mock.Of<IAuthenticationSessionService>(),
            options => options.AccessDeniedPath = "/forbidden");
        var context = CreateContext(provider);

        await provider.GetRequiredService<IAuthenticationService>().ForbidAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "/admin/reports" });

        Assert.That(
            context.Response.Headers.Location.ToString(),
            Is.EqualTo("http://localhost/forbidden?ReturnUrl=%2Fadmin%2Freports"));
    }

    [Test]
    public async Task ForbidAsyncShouldRedirectToAccessDeniedWithoutReturnUrlWhenRedirectUriIsMissing()
    {
        await using var provider = CreateProvider(
            Mock.Of<IAuthenticationSessionService>(),
            options => options.AccessDeniedPath = "/forbidden");
        var context = CreateContext(provider);

        await provider.GetRequiredService<IAuthenticationService>().ForbidAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties());

        Assert.That(context.Response.Headers.Location.ToString(), Is.EqualTo("http://localhost/forbidden"));
    }

    [Test]
    public async Task ForbidAsyncShouldUseBaseBehaviorWhenAccessDeniedPathIsMissing()
    {
        await using var provider = CreateProvider(Mock.Of<IAuthenticationSessionService>());
        var context = CreateContext(provider);

        await provider.GetRequiredService<IAuthenticationService>().ForbidAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties());

        Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
    }

    [Test]
    public async Task ForbidAsyncShouldReturnForbiddenForApiRequests()
    {
        await using var provider = CreateProvider(
            Mock.Of<IAuthenticationSessionService>(),
            options => options.AccessDeniedPath = "/forbidden");
        var context = CreateContext(provider);
        context.Request.Headers.XRequestedWith = "XMLHttpRequest";

        await provider.GetRequiredService<IAuthenticationService>().ForbidAsync(
            context,
            AshlarSessionAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "/admin/reports" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
            Assert.That(context.Response.Headers.Location.ToString(), Is.Empty);
        }
    }

    [Test]
    public void ConstructorShouldThrowOnNullSessionService()
    {
        var options = new Mock<IOptionsMonitor<AshlarSessionAuthenticationOptions>>();

        Assert.Throws<ArgumentNullException>(() => _ = new AshlarSessionAuthenticationHandler(
            options.Object,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            // ReSharper disable once NullableWarningSuppressionIsUsed
            null!));
    }

    private static ServiceProvider CreateProvider(
        IAuthenticationSessionService sessionService,
        Action<AshlarSessionAuthenticationOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(sessionService);
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
            },
            Request = { Scheme = "http", Host = new HostString("localhost") }
        };
        return context;
    }

    private static Task<AuthenticateResult> AuthenticateAsync(
        IServiceProvider provider,
        HttpContext context,
        string scheme = AshlarSessionAuthenticationDefaults.AuthenticationScheme)
    {
        return provider.GetRequiredService<IAuthenticationService>().AuthenticateAsync(context, scheme);
    }

    private static AuthenticationSession CreateSession(Guid sessionId, Guid userId, DateTimeOffset expiresAt, Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TenantId = tenantId,
            TokenHash = "hashed-token",
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1),
            ExpiresAt = expiresAt
        };
    }

    private static ValidateAuthenticationSessionResult CreateSuccessfulValidation(
        AuthenticationSession session,
        AuthenticationSession? validatedSession = null)
    {
        var capability = Activator.CreateInstance(typeof(ValidatedAuthenticationSession),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic, null, [validatedSession ?? session], null);
        return (ValidateAuthenticationSessionResult)Activator.CreateInstance(typeof(ValidateAuthenticationSessionResult),
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic, null,
            [AuthenticationSessionValidationStatus.Succeeded, capability], null)!;
    }
}
