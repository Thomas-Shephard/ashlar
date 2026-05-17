using System.Globalization;
using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Authorization;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarStepUpAuthorizationHandlerTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] TotpAndPasskeyFactors = [AuthenticationFactorTypes.Totp, AuthenticationFactorTypes.Passkey];
    private static readonly AuthenticationProviderKey[] PasskeyProvider = [AuthenticationProviderKey.Passkey];

    [Test]
    public async Task HandleAsyncShouldFailForUnauthenticatedPrincipal()
    {
        var requirement = new AshlarStepUpRequirement(TimeSpan.FromMinutes(5));
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(new ClaimsIdentity()), null);
        var handler = CreateHandler();

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task AuthorizationPolicyShouldChallengeUnauthenticatedUsersThroughRequireAuthenticatedUser()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(new StepUpAuthenticationService(new FixedTimeProvider(Now)));
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfa());
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync(AshlarStepUpPolicyNames.FreshMfa);

        Assert.That(policy?.Requirements.OfType<DenyAnonymousAuthorizationRequirement>(), Has.Exactly(1).Items);
    }

    [Test]
    public async Task HandleAsyncShouldFailForAuthenticatedSessionWithoutAdditionalVerification()
    {
        var session = CreateSession();
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldSucceedForFreshTotpVerification()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(TimeSpan.FromMinutes(5), allowedFactors: [AuthenticationFactorTypes.Totp]));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldSucceedFromClaimsWhenCurrentSessionItemIsMissing()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailForExpiredVerification()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-10);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailForDisallowedFactor()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(TimeSpan.FromMinutes(5), allowedFactors: [AuthenticationFactorTypes.Passkey]));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailForDisallowedProvider()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(TimeSpan.FromMinutes(5), allowedProviders: [AuthenticationProviderKey.Passkey]));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldSucceedForAllowedPasskeyProviderAndFactor()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = AuthenticationProviderKey.Passkey;
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Passkey;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedProviders: [AuthenticationProviderKey.Passkey],
                allowedFactors: [AuthenticationFactorTypes.Passkey]));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyForMalformedStepUpClaims()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session).Where(c => c.Type != AshlarClaimTypes.AdditionalVerificationAt).ToList();
        claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationAt, "not-a-unix-time"));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var requirement = new AshlarStepUpRequirement(TimeSpan.FromMinutes(5));
        var context = new AuthorizationHandlerContext([requirement], principal, null);

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyWhenSessionClaimIsMissing()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session).Where(c => c.Type != AshlarClaimTypes.SessionId).ToArray();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var requirement = new AshlarStepUpRequirement(TimeSpan.FromMinutes(5));
        var context = new AuthorizationHandlerContext([requirement], principal, null);

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenCurrentSessionDoesNotMatchClaims()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var currentSession = CreateSession();
        currentSession.AdditionalVerificationAt = session.AdditionalVerificationAt;
        currentSession.AdditionalVerificationProvider = session.AdditionalVerificationProvider;
        currentSession.AdditionalVerificationFactor = session.AdditionalVerificationFactor;
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await CreateHandler(currentSession).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyForMalformedPrimaryProviderClaims()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        session.PrimaryProvider = null;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderType, ProviderType.EmailCode.Value));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyForOutOfRangeTimeClaim()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session).Where(c => c.Type != AshlarClaimTypes.AuthenticatedAt).ToList();
        claims.Add(new Claim(AshlarClaimTypes.AuthenticatedAt, long.MaxValue.ToString(CultureInfo.InvariantCulture)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyForInvalidProviderClaim()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderType, ProviderType.Mfa.Value));
        claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderName, " "));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public void AddAshlarAspNetCoreAuthorizationShouldWireStepUpHandler()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        services.AddSingleton(Mock.Of<Ashlar.Authorization.Abstractions.IAuthorizationEvaluator>());
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfa());
        using var provider = services.BuildServiceProvider();

        var handlers = provider.GetServices<IAuthorizationHandler>();

        Assert.That(handlers.OfType<AshlarStepUpAuthorizationHandler>(), Has.Exactly(1).Items);
    }

    [Test]
    public async Task AddAshlarStepUpPolicyShouldRegisterNamedPolicy()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        services.AddAshlarAspNetCoreAuthorization(options =>
        {
            options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(20);
            options.StepUp.AllowedProviders.Add(AuthenticationProviderKey.Passkey);
            options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
            options.AddAshlarStepUpPolicy("Sensitive", stepUp =>
            {
                stepUp.FreshnessWindow = TimeSpan.FromMinutes(3);
                stepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
            });
        });
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync("Sensitive");
        var requirement = policy?.Requirements.OfType<AshlarStepUpRequirement>().SingleOrDefault();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement, Is.Not.Null);
            Assert.That(requirement?.FreshnessWindow, Is.EqualTo(TimeSpan.FromMinutes(3)));
            Assert.That(requirement?.AllowedProviders, Is.EquivalentTo(PasskeyProvider));
            Assert.That(requirement?.AllowedFactors, Is.EquivalentTo(TotpAndPasskeyFactors));
        }
    }

    [Test]
    public void RequireFreshMfaEndpointHelperShouldAddDefaultPolicy()
    {
        var builder = WebApplication.CreateSlimBuilder();
        var app = builder.Build();
        app.MapGet("/sensitive", () => "ok").RequireFreshMfa();

        var dataSource = ((IEndpointRouteBuilder)app).DataSources.Single();
        var metadata = dataSource.Endpoints.Single().Metadata.GetOrderedMetadata<IAuthorizeData>();

        Assert.That(metadata.Single().Policy, Is.EqualTo(AshlarStepUpPolicyNames.FreshMfa));
    }

    [Test]
    public void RequireFreshMfaEndpointHelperShouldRejectNullBuilder()
    {
        RouteHandlerBuilder builder = null!;

        Assert.Throws<ArgumentNullException>(() => builder.RequireFreshMfa());
    }

    [Test]
    public void HandlerConstructorShouldRejectNullDependencies()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarStepUpAuthorizationHandler(null!, new HttpContextAccessor()));
            Assert.Throws<ArgumentNullException>(() => _ = new AshlarStepUpAuthorizationHandler(Mock.Of<IStepUpAuthenticationService>(), null!));
        }
    }

    [Test]
    public void RequirementShouldRejectNonPositiveFreshnessWindow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _ = new AshlarStepUpRequirement(TimeSpan.Zero));
    }

    private static AshlarStepUpAuthorizationHandler CreateHandler(AuthenticationSession? session = null)
    {
        var httpContextAccessor = new HttpContextAccessor();
        if (session != null)
        {
            httpContextAccessor.HttpContext = new DefaultHttpContext();
            httpContextAccessor.HttpContext.Items[AshlarHttpContextItems.AuthenticationSession] = session;
        }

        return new AshlarStepUpAuthorizationHandler(
            new StepUpAuthenticationService(new FixedTimeProvider(Now)),
            httpContextAccessor);
    }

    private static AuthorizationHandlerContext CreateContext(AuthenticationSession session, AshlarStepUpRequirement requirement)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(CreateClaims(session), "TestAuth"));
        return new AuthorizationHandlerContext([requirement], principal, null);
    }

    private static List<Claim> CreateClaims(AuthenticationSession session)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, session.UserId.ToString("D")),
            new(AshlarClaimTypes.SessionId, session.Id.ToString("D"))
        };
        if (session.AuthenticatedAt.HasValue)
        {
            claims.Add(new Claim(
                AshlarClaimTypes.AuthenticatedAt,
                session.AuthenticatedAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        }

        if (session.PrimaryProvider.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderType, session.PrimaryProvider.Value.TypeValueOrUnknown));
            claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderName, session.PrimaryProvider.Value.Name));
        }

        if (session.AdditionalVerificationAt.HasValue)
        {
            claims.Add(new Claim(
                AshlarClaimTypes.AdditionalVerificationAt,
                session.AdditionalVerificationAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        }

        if (session.AdditionalVerificationProvider.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderType, session.AdditionalVerificationProvider.Value.TypeValueOrUnknown));
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderName, session.AdditionalVerificationProvider.Value.Name));
        }

        if (!string.IsNullOrWhiteSpace(session.AdditionalVerificationFactor))
        {
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationFactor, session.AdditionalVerificationFactor));
        }

        return claims;
    }

    private static AuthenticationSession CreateSession()
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TokenHash = "hash",
            CreatedAt = Now.AddHours(-1),
            AuthenticatedAt = Now.AddHours(-1),
            PrimaryProvider = AuthenticationProviderKey.EmailCode,
            ExpiresAt = Now.AddHours(1)
        };
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
