using System.Globalization;
using System.Security.Claims;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Authorization;
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
    public async Task HandleAsyncShouldFailForPrincipalWithoutIdentity()
    {
        var requirement = new AshlarStepUpRequirement(TimeSpan.FromMinutes(5));
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(), null);
        var handler = CreateHandler();

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task AuthorizationPolicyShouldChallengeUnauthenticatedUsersThroughRequireAuthenticatedUser()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(new StepUpAuthenticationService(new FixedTimeProvider(Now)));
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfa());
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync(AshlarStepUpPolicyNames.FreshMfa);

        Assert.That(policy?.Requirements.OfType<DenyAnonymousAuthorizationRequirement>(), Has.Exactly(1).Items);
    }

    [Test]
    public async Task ConditionalAuthorizationPolicyShouldChallengeUnauthenticatedUsersThroughRequireAuthenticatedUser()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(new StepUpAuthenticationService(new FixedTimeProvider(Now)));
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfaIfAvailable());
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync(AshlarStepUpPolicyNames.FreshMfaIfAvailable);

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
    public async Task HandleAsyncShouldMatchSessionTimeClaimsAtSerializedUnixSecondPrecision()
    {
        var session = CreateSession();
        session.AuthenticatedAt = Now.AddHours(-1).AddMilliseconds(123);
        session.AdditionalVerificationAt = Now.AddMinutes(-2).AddMilliseconds(456);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailFromClaimsWhenCurrentSessionItemIsMissing()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
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
    public async Task HandleAsyncShouldFailForNonAshlarPrincipalWithAshlarClaimsWhenCurrentSessionItemIsMissing()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var principal = new ClaimsPrincipal(new ClaimsIdentity(CreateClaims(session), "ExternalOidc"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler().HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenHttpContextHasNoCurrentSessionItem()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var httpContextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        var handler = new AshlarStepUpAuthorizationHandler(
            new StepUpAuthenticationService(new FixedTimeProvider(Now)),
            httpContextAccessor);
        var context = CreateContext(session, new AshlarStepUpRequirement(TimeSpan.FromMinutes(5)));

        await handler.HandleAsync(context);

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
    public async Task HandleAsyncShouldSucceedForConditionalPolicyWhenNoEligibleFactorIsAvailable()
    {
        var session = CreateSession();
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(session, CreateAccountSecurityService(session.UserId)).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldSucceedForConditionalPolicyWithEligibleFreshTotp()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            session,
            CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Totp)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailForConditionalPolicyWithEligibleStaleTotp()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-10);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            session,
            CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Totp)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailForUnauthenticatedPrincipalWithConditionalRequirement()
    {
        var requirement = new AshlarStepUpRequirement(
            TimeSpan.FromMinutes(5),
            allowedFactors: [AuthenticationFactorTypes.Totp],
            mode: AshlarStepUpMode.IfAvailable);
        var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(new ClaimsIdentity()), null);

        await CreateHandler(accountSecurity: Mock.Of<IAccountSecurityService>()).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailForConditionalPolicyWithEligibleMissingTotpVerification()
    {
        var session = CreateSession();
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            session,
            CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Totp)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldTreatDisallowedPasskeyFactorAsUnavailableForConditionalPolicy()
    {
        var session = CreateSession();
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            session,
            CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Passkey)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldTreatUnusableEligibleFactorAsUnavailableForConditionalPolicy()
    {
        var session = CreateSession();
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            session,
            CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Totp, isUsable: false)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldRequireFreshPasskeyWhenPasskeyIsAllowedForConditionalPolicy()
    {
        var session = CreateSession();
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Passkey],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            session,
            CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Passkey)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldDenyConditionalPolicyWhenPostureLookupFails()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var accountSecurity = new Mock<IAccountSecurityService>(MockBehavior.Strict);
        accountSecurity
            .Setup(service => service.GetUserSecurityPostureAsync(
                session.UserId,
                It.IsAny<AccountSecurityPostureRequest?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Failure<AccountSecurityPosture>(AshlarFailureCodes.UserNotFound));
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(session, accountSecurity.Object).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldDenyConditionalPolicyWhenPostureLookupFailsWithValue()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var posture = new AccountSecurityPosture(
            session.UserId,
            AccountState: UserAccountState.Active,
            IsEmailVerified: true,
            CanSignIn: true,
            PrimaryCredentials: [],
            AdditionalVerificationFactors: [CreateFactor(AuthenticationFactorTypes.Totp)],
            Policy: new AccountSecurityPolicyPosture(false, [], [], true, true, [], [], false),
            CredentialInventory: [],
            ActiveSessionCount: 1,
            RecentSecurityEventCount: null);
        var accountSecurity = new Mock<IAccountSecurityService>(MockBehavior.Strict);
        accountSecurity
            .Setup(service => service.GetUserSecurityPostureAsync(
                session.UserId,
                It.IsAny<AccountSecurityPostureRequest?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AccountSecurityPosture>(false, posture));
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(session, accountSecurity.Object).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldDenyConditionalPolicyWhenAccountSecurityServiceIsUnavailable()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldDenyConditionalPolicyWhenPostureValueIsMissing()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var accountSecurity = new Mock<IAccountSecurityService>(MockBehavior.Strict);
        accountSecurity
            .Setup(service => service.GetUserSecurityPostureAsync(
                session.UserId,
                It.IsAny<AccountSecurityPostureRequest?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Result<AccountSecurityPosture>(true));
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(session, accountSecurity.Object).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldPassSessionTenantToConditionalPostureLookup()
    {
        var tenantId = Guid.NewGuid();
        var session = CreateSession(tenantId);
        var accountSecurity = new Mock<IAccountSecurityService>(MockBehavior.Strict);
        accountSecurity
            .Setup(service => service.GetUserSecurityPostureAsync(
                session.UserId,
                It.Is<AccountSecurityPostureRequest>(request => request.Tenant != null && request.Tenant.TenantId == tenantId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AccountSecurityPosture(
                session.UserId,
                AccountState: UserAccountState.Active,
                IsEmailVerified: true,
                CanSignIn: true,
                PrimaryCredentials: [],
                AdditionalVerificationFactors: [],
                Policy: new AccountSecurityPolicyPosture(false, [], [], false, true, [], [], false),
                CredentialInventory: [],
                ActiveSessionCount: 1,
                RecentSecurityEventCount: null)));
        var context = new AuthorizationHandlerContext(
            [new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable)],
            new ClaimsPrincipal(new ClaimsIdentity(CreateClaims(session), "TestAuth")),
            null);

        await CreateHandler(session, accountSecurity.Object).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
    }

    [Test]
    public async Task HandleAsyncShouldFailForConditionalPolicyWhenCurrentSessionItemIsMissing()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(accountSecurity: CreateAccountSecurityService(session.UserId, [CreateFactor(AuthenticationFactorTypes.Totp)])).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailConditionalPolicyWithoutHttpContext()
    {
        var session = CreateSession();
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));

        await CreateHandler(
            accountSecurity: CreateAccountSecurityService(session.UserId)).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldResolveConditionalPostureServiceFromRequestServices()
    {
        var session = CreateSession();
        var services = new ServiceCollection();
        services.AddSingleton(CreateAccountSecurityService(session.UserId));
        await using var provider = services.BuildServiceProvider();
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext { RequestServices = provider }
        };
        httpContextAccessor.HttpContext.Items[AshlarHttpContextItems.AuthenticationSession] = session;
        var context = CreateContext(
            session,
            new AshlarStepUpRequirement(
                TimeSpan.FromMinutes(5),
                allowedFactors: [AuthenticationFactorTypes.Totp],
                mode: AshlarStepUpMode.IfAvailable));
        var handler = new AshlarStepUpAuthorizationHandler(
            new StepUpAuthenticationService(new FixedTimeProvider(Now)),
            httpContextAccessor);

        await handler.HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.True);
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

        await CreateHandler(session).HandleAsync(context);

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
    public async Task HandleAsyncShouldFailWhenCurrentSessionUserDoesNotMatchClaims()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var currentSession = new AuthenticationSession
        {
            Id = session.Id,
            UserId = Guid.NewGuid(),
            TokenHash = "hash",
            CreatedAt = session.CreatedAt,
            ExpiresAt = session.ExpiresAt,
            AdditionalVerificationAt = session.AdditionalVerificationAt,
            AdditionalVerificationProvider = session.AdditionalVerificationProvider,
            AdditionalVerificationFactor = session.AdditionalVerificationFactor
        };
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

        await CreateHandler(session).HandleAsync(context);

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

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyForTimeClaimBeforeUnixTimeRange()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session).Where(c => c.Type != AshlarClaimTypes.AuthenticatedAt).ToList();
        claims.Add(new Claim(AshlarClaimTypes.AuthenticatedAt, long.MinValue.ToString(CultureInfo.InvariantCulture)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler(session).HandleAsync(context);

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

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenTenantClaimConflictsWithCurrentSession()
    {
        var session = CreateSession(Guid.NewGuid());
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session).Where(c => c.Type != AshlarClaimTypes.TenantId).ToList();
        claims.Add(new Claim(AshlarClaimTypes.TenantId, Guid.NewGuid().ToString("D")));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenTenantClaimIsMalformed()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.TenantId, "not-a-tenant"));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenTenantClaimExistsForGlobalSession()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.TenantId, Guid.NewGuid().ToString("D")));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenTimeClaimExistsForMissingSessionTime()
    {
        var session = CreateSession();
        session.AuthenticatedAt = null;
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.AuthenticatedAt, Now.AddHours(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailWhenProviderClaimsExistForMissingSessionProvider()
    {
        var session = CreateSession();
        session.PrimaryProvider = null;
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationProvider = new AuthenticationProviderKey(ProviderType.Mfa, AuthenticationFactorTypes.Totp);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderType, ProviderType.EmailCode.Value));
        claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderName, "EmailCode"));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
        var context = new AuthorizationHandlerContext([new AshlarStepUpRequirement(TimeSpan.FromMinutes(5))], principal, null);

        await CreateHandler(session).HandleAsync(context);

        Assert.That(context.HasSucceeded, Is.False);
    }

    [Test]
    public async Task HandleAsyncShouldFailSafelyForMissingAdditionalProviderTypeClaim()
    {
        var session = CreateSession();
        session.AdditionalVerificationAt = Now.AddMinutes(-2);
        session.AdditionalVerificationFactor = AuthenticationFactorTypes.Totp;
        var claims = CreateClaims(session);
        claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderName, AuthenticationFactorTypes.Totp));
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
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddSingleton(Mock.Of<Ashlar.Authorization.Abstractions.IAuthorizationEvaluator>());
        services.AddAshlarAspNetCoreAuthorization();
        using var provider = services.BuildServiceProvider();

        var handlers = provider.GetServices<IAuthorizationHandler>();

        Assert.That(handlers.OfType<AshlarStepUpAuthorizationHandler>(), Has.Exactly(1).Items);
    }

    [Test]
    public async Task AddAshlarAspNetCoreAuthorizationShouldRegisterDefaultStrictPolicy()
    {
        var requirement = await ResolveStepUpRequirementAsync(AshlarStepUpPolicyNames.FreshMfa);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement, Is.Not.Null);
            Assert.That(requirement?.Mode, Is.EqualTo(AshlarStepUpMode.Required));
        }
    }

    [Test]
    public async Task AddAshlarAspNetCoreAuthorizationShouldRegisterDefaultConditionalPolicy()
    {
        var requirement = await ResolveStepUpRequirementAsync(AshlarStepUpPolicyNames.FreshMfaIfAvailable);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement, Is.Not.Null);
            Assert.That(requirement?.Mode, Is.EqualTo(AshlarStepUpMode.IfAvailable));
        }
    }

    [Test]
    public async Task AddAshlarStepUpPolicyShouldRegisterNamedPolicy()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
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
    public async Task RequireFreshMfaShouldReplaceDefaultStrictPolicy()
    {
        var requirement = await ResolveStepUpRequirementAsync(
            AshlarStepUpPolicyNames.FreshMfa,
            options =>
            {
                options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(20);
                options.RequireFreshMfa(stepUp =>
                {
                    stepUp.FreshnessWindow = TimeSpan.FromMinutes(3);
                    stepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
                });
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement, Is.Not.Null);
            Assert.That(requirement?.FreshnessWindow, Is.EqualTo(TimeSpan.FromMinutes(3)));
            Assert.That(requirement?.Mode, Is.EqualTo(AshlarStepUpMode.Required));
            Assert.That(requirement?.AllowedFactors, Is.EquivalentTo([AuthenticationFactorTypes.Passkey]));
        }
    }

    [Test]
    public async Task RequireFreshMfaIfAvailableShouldReplaceDefaultConditionalPolicy()
    {
        var requirement = await ResolveStepUpRequirementAsync(
            AshlarStepUpPolicyNames.FreshMfaIfAvailable,
            options =>
            {
                options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(20);
                options.RequireFreshMfaIfAvailable(stepUp =>
                {
                    stepUp.FreshnessWindow = TimeSpan.FromMinutes(4);
                    stepUp.AllowedFactors.Clear();
                    stepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
                });
            });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement, Is.Not.Null);
            Assert.That(requirement?.FreshnessWindow, Is.EqualTo(TimeSpan.FromMinutes(4)));
            Assert.That(requirement?.Mode, Is.EqualTo(AshlarStepUpMode.IfAvailable));
            Assert.That(requirement?.AllowedFactors, Is.EquivalentTo([AuthenticationFactorTypes.Passkey]));
        }
    }

    [Test]
    public async Task RequireFreshMfaIfAvailableShouldRegisterDefaultConditionalPolicy()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfaIfAvailable());
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync(AshlarStepUpPolicyNames.FreshMfaIfAvailable);
        var requirement = policy?.Requirements.OfType<AshlarStepUpRequirement>().SingleOrDefault();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement, Is.Not.Null);
            Assert.That(requirement?.Mode, Is.EqualTo(AshlarStepUpMode.IfAvailable));
            Assert.That(requirement?.AllowedFactors, Is.EquivalentTo(new[]
            {
                AuthenticationFactorTypes.Totp,
                AuthenticationFactorTypes.RecoveryCode,
                AuthenticationFactorTypes.Passkey
            }));
        }
    }

    [Test]
    public async Task AddAshlarStepUpIfAvailablePolicyShouldPreserveConfiguredFactorsAndApplyCallback()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddAshlarAspNetCoreAuthorization(options =>
        {
            options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
            options.AddAshlarStepUpIfAvailablePolicy("Adaptive", stepUp =>
            {
                stepUp.FreshnessWindow = TimeSpan.FromMinutes(2);
                stepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
            });
        });
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync("Adaptive");
        var requirement = policy?.Requirements.OfType<AshlarStepUpRequirement>().SingleOrDefault();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement?.FreshnessWindow, Is.EqualTo(TimeSpan.FromMinutes(2)));
            Assert.That(requirement?.Mode, Is.EqualTo(AshlarStepUpMode.IfAvailable));
            Assert.That(requirement?.AllowedFactors, Is.EquivalentTo(TotpAndPasskeyFactors));
        }
    }

    [Test]
    public async Task RequireFreshMfaEndpointHelperShouldAddRegisteredDefaultPolicy()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        builder.Services.AddSingleton(Mock.Of<IAccountSecurityService>());
        builder.Services.AddAshlarAspNetCoreAuthorization();
        var app = builder.Build();
        app.MapGet("/sensitive", () => "ok").RequireFreshMfa();

        var dataSource = ((IEndpointRouteBuilder)app).DataSources.Single();
        var metadata = dataSource.Endpoints.Single().Metadata.GetOrderedMetadata<IAuthorizeData>();
        var policyProvider = app.Services.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = await policyProvider.GetPolicyAsync(metadata.Single().Policy!);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(metadata.Single().Policy, Is.EqualTo(AshlarStepUpPolicyNames.FreshMfa));
            Assert.That(policy?.Requirements.OfType<AshlarStepUpRequirement>(), Has.Exactly(1).Items);
        }
    }

    [Test]
    public void RequireFreshMfaEndpointHelperShouldRejectNullBuilder()
    {
        RouteHandlerBuilder builder = null!;

        Assert.Throws<ArgumentNullException>(() => builder.RequireFreshMfa());
    }

    [Test]
    public async Task RequireFreshMfaIfAvailableEndpointHelperShouldAddRegisteredDefaultPolicy()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        builder.Services.AddSingleton(Mock.Of<IAccountSecurityService>());
        builder.Services.AddAshlarAspNetCoreAuthorization();
        var app = builder.Build();
        app.MapGet("/sensitive", () => "ok").RequireFreshMfaIfAvailable();

        var dataSource = ((IEndpointRouteBuilder)app).DataSources.Single();
        var metadata = dataSource.Endpoints.Single().Metadata.GetOrderedMetadata<IAuthorizeData>();
        var policyProvider = app.Services.GetRequiredService<IAuthorizationPolicyProvider>();
        var policy = await policyProvider.GetPolicyAsync(metadata.Single().Policy!);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(metadata.Single().Policy, Is.EqualTo(AshlarStepUpPolicyNames.FreshMfaIfAvailable));
            Assert.That(policy?.Requirements.OfType<AshlarStepUpRequirement>(), Has.Exactly(1).Items);
        }
    }

    [Test]
    public void RequireFreshMfaIfAvailableEndpointHelperShouldRejectNullBuilder()
    {
        RouteHandlerBuilder builder = null!;

        Assert.Throws<ArgumentNullException>(() => builder.RequireFreshMfaIfAvailable());
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

    private static AshlarStepUpAuthorizationHandler CreateHandler(
        AuthenticationSession? session = null,
        IAccountSecurityService? accountSecurity = null)
    {
        var httpContextAccessor = new HttpContextAccessor();
        if (session != null)
        {
            httpContextAccessor.HttpContext = new DefaultHttpContext();
            httpContextAccessor.HttpContext.Items[AshlarHttpContextItems.AuthenticationSession] = session;
        }

        return new AshlarStepUpAuthorizationHandler(
            new StepUpAuthenticationService(new FixedTimeProvider(Now)),
            httpContextAccessor,
            accountSecurity);
    }

    private static async Task<AshlarStepUpRequirement?> ResolveStepUpRequirementAsync(
        string policyName,
        Action<AshlarAuthorizationOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IStepUpAuthenticationService>(Mock.Of<IStepUpAuthenticationService>());
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddAshlarAspNetCoreAuthorization(configure);
        await using var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policyProvider.GetPolicyAsync(policyName);

        return policy?.Requirements.OfType<AshlarStepUpRequirement>().SingleOrDefault();
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
        if (session.TenantId.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.TenantId, session.TenantId.Value.ToString("D")));
        }

        if (session.AuthenticatedAt.HasValue)
        {
            claims.Add(new Claim(
                AshlarClaimTypes.AuthenticatedAt,
                session.AuthenticatedAt.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        }

        if (session.PrimaryProvider.HasValue)
        {
            claims.Add(new Claim(AshlarClaimTypes.PrimaryProviderType, session.PrimaryProvider.Value.StorageTypeValue));
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
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderType, session.AdditionalVerificationProvider.Value.StorageTypeValue));
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationProviderName, session.AdditionalVerificationProvider.Value.Name));
        }

        if (!string.IsNullOrWhiteSpace(session.AdditionalVerificationFactor))
        {
            claims.Add(new Claim(AshlarClaimTypes.AdditionalVerificationFactor, session.AdditionalVerificationFactor));
        }

        return claims;
    }

    private static AuthenticationSession CreateSession(Guid? tenantId = null)
    {
        return new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            TenantId = tenantId,
            TokenHash = "hash",
            CreatedAt = Now.AddHours(-1),
            AuthenticatedAt = Now.AddHours(-1),
            PrimaryProvider = AuthenticationProviderKey.EmailCode,
            ExpiresAt = Now.AddHours(1)
        };
    }

    private static IAccountSecurityService CreateAccountSecurityService(
        Guid userId,
        IReadOnlyList<AdditionalVerificationFactorPosture>? factors = null)
    {
        var accountSecurity = new Mock<IAccountSecurityService>(MockBehavior.Strict);
        accountSecurity
            .Setup(service => service.GetUserSecurityPostureAsync(
                userId,
                It.IsAny<AccountSecurityPostureRequest?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AccountSecurityPosture(
                userId,
                AccountState: UserAccountState.Active,
                IsEmailVerified: true,
                CanSignIn: true,
                PrimaryCredentials: [],
                AdditionalVerificationFactors: factors ?? [],
                Policy: new AccountSecurityPolicyPosture(
                    IsAdditionalVerificationRequired: false,
                    RequiredFactorTypes: [],
                    AllowedFactorTypes: [],
                    HasUsableAdditionalVerificationFactor: factors?.Any(factor => factor.IsUsable) == true,
                    IsReadyForAdditionalVerification: true,
                    MissingRequiredFactorTypes: [],
                    MissingRequiredFactorDisplayNames: [],
                    IsLockedOutByPolicy: false),
                CredentialInventory: [],
                ActiveSessionCount: 1,
                RecentSecurityEventCount: null)));
        return accountSecurity.Object;
    }

    private static AdditionalVerificationFactorPosture CreateFactor(string factorType, bool isUsable = true)
    {
        return new AdditionalVerificationFactorPosture(
            factorType,
            factorType,
            IsConfigured: true,
            IsUsable: isUsable,
            Providers: []);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return now;
        }
    }
}
