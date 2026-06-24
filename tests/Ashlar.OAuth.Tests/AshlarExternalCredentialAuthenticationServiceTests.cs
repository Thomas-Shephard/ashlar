using System.Security.Claims;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.OAuth.Providers.GitHub;
using Ashlar.OAuth.Providers.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarExternalCredentialAuthenticationServiceTests
{
    [Test]
    public async Task CompleteExternalAssertionShouldMapMatchingExternalTicketWithoutCallingAuthenticationPipeline()
    {
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        var service = CreateService(limiter.Object);
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }

        limiter.VerifyNoOtherCalls();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnProviderMismatchForOidcTicketWithoutProviderType()
    {
        var limiter = CreateAllowingLimiter();
        var service = CreateService(limiter.Object);
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreatePrincipal("subject"),
                CreateProperties("Google", "Google", includeProviderType: false),
                "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));

        limiter.Verify(l => l.CheckAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), new AuthenticationProviderKey(ProviderType.Oidc, "Google"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task CompleteExternalAssertionShouldMapGitHubTicketAsOAuthAssertion()
    {
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        var service = CreateService(limiter.Object, includeGitHub: true);
        var httpContext = CreateHttpContextWithExternalTicket("GitHub", "GitHub", ProviderType.OAuth, CreateGitHubPrincipal("12345"));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "GitHub");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("12345"));
            Assert.That(result.Assertion?.Claims["login"], Is.EqualTo(["octocat"]));
        }

        limiter.VerifyNoOtherCalls();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnProviderMismatchForWrongProviderType()
    {
        var service = CreateService(new AuthenticationResponse(false), includeGitHub: true);
        var httpContext = CreateHttpContextWithExternalTicket("GitHub", "GitHub", ProviderType.Oidc, CreateGitHubPrincipal("12345"));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "GitHub");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnProviderMismatchForOAuthTicketWithoutProviderType()
    {
        var service = CreateService(new AuthenticationResponse(false), includeGitHub: true);
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreateGitHubPrincipal("12345"),
                CreateProperties("GitHub", "GitHub", includeProviderType: false),
                "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "GitHub");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldUseConfiguredOAuth2ProviderKeyClaim()
    {
        var limiter = CreateAllowingLimiter();
        var service = CreateService(limiter.Object, options => options.AddOAuth2Provider("CustomOAuth", "uid", _ => { }));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("uid", "stable-uid"), new Claim("id", "not-used")], "oauth"));
        var httpContext = CreateHttpContextWithExternalTicket("CustomOAuth", "CustomOAuth", ProviderType.OAuth, principal);

        var result = await service.CompleteExternalAssertionAsync(httpContext, "CustomOAuth");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "CustomOAuth")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("stable-uid"));
        }

        limiter.VerifyNoOtherCalls();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldUseExplicitUnsafeOAuth2ProviderKeyClaimType()
    {
        var limiter = CreateAllowingLimiter();
        var service = CreateService(limiter.Object, options => options.AddOAuth2ProviderWithUnsafeProviderKeyClaimType("CustomOAuth", "email", _ => { }));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("email", "stable-provider-id")], "oauth"));
        var httpContext = CreateHttpContextWithExternalTicket("CustomOAuth", "CustomOAuth", ProviderType.OAuth, principal);

        var result = await service.CompleteExternalAssertionAsync(httpContext, "CustomOAuth");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "CustomOAuth")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("stable-provider-id"));
        }

        limiter.VerifyNoOtherCalls();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldLeaveSessionIssuanceToHostOrchestration()
    {
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        var orchestrator = new Mock<IAuthenticationOrchestrator>(MockBehavior.Strict);
        var service = CreateService(limiter.Object);
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");
        var user = new Mock<IUser>();
        AuthenticationProviderKey? observedProvider = null;

        orchestrator.Setup(o => o.AuthenticateAsync(
                It.IsAny<AuthenticationContext>(),
                It.IsAny<IAuthenticationAssertion>(),
                null,
                It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, MfaOrchestrationOptions?, CancellationToken>((_, assertion, _, _) =>
            {
                observedProvider = ((ExternalIdentityAssertion)assertion).ProviderIdentity;
            })
            .ReturnsAsync(new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user.Object));

        var assertionResult = await service.CompleteExternalAssertionAsync(httpContext, "Google");
        var authentication = await orchestrator.Object.AuthenticateAsync(new AuthenticationContext(), assertionResult.Assertion!, cancellationToken: CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertionResult.Succeeded, Is.True);
            Assert.That(authentication.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(authentication.User, Is.SameAs(user.Object));
            Assert.That(observedProvider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
        }

        limiter.VerifyNoOtherCalls();
        orchestrator.VerifyAll();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnProviderMismatchForMismatchedExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Microsoft", "Microsoft", "subject");

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));
            Assert.That(result.Succeeded, Is.False);
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnAuthenticationFailedForFailedTicket()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContext(new TestAuthenticationService(AuthenticateResult.Fail("failed")));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.AuthenticationFailed));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnProviderMismatchWhenTicketPropertiesAreMissing()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("subject"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity([], "oidc")),
                CreateProperties("Google", "Google"),
                "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));
        var httpContext = CreateHttpContextWithExternalTicket(" ", "Google", "subject");

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnRateLimitedWhenMissingSubjectIsRateLimited()
    {
        var limiter = CreateBlockedLimiter();
        var service = CreateService(limiter.Object);
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity([], "oidc")),
                CreateProperties("Google", "Google"),
                "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.RateLimited));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnRateLimitedWhenInvalidProviderNameIsRateLimited()
    {
        var limiter = CreateBlockedLimiter();
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }), limiter.Object);
        var httpContext = CreateHttpContextWithExternalTicket(" ", "Google", "subject");

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.RateLimited));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldClearExternalTicketForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalAssertionAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldClearUnsupportedProviderTicketWhenRequestIsCanceled()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var result = await service.CompleteExternalAssertionAsync(httpContext, " ", cts.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldRateLimitUnsupportedProviderBeforeReturning()
    {
        AuthenticationContext? observedContext = null;
        IAuthenticationAssertion? observedAssertion = null;
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        limiter.Setup(l => l.CheckAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, AuthenticationProviderKey, CancellationToken>((context, assertion, _, _) =>
            {
                observedContext = context;
                observedAssertion = assertion;
            })
            .ReturnsAsync(RateLimitDecision.Allow());
        var service = CreateService(limiter.Object);
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        httpContext.TraceIdentifier = "trace-unsupported";

        var result = await service.CompleteExternalAssertionAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.UnsupportedProvider));
            Assert.That(observedContext?.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(observedContext?.CorrelationId, Is.EqualTo("trace-unsupported"));
            Assert.That(observedAssertion, Is.Not.InstanceOf<ICredentialKeyAuthenticationAssertion>());
            Assert.That(observedAssertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey((ProviderType)"EXTERNAL_UNSUPPORTED", "unsupported")));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }

        limiter.VerifyAll();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldNormalizeUnsupportedProviderNameForRateLimitKey()
    {
        IAuthenticationAssertion? observedAssertion = null;
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>(MockBehavior.Strict);
        limiter.Setup(l => l.CheckAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, AuthenticationProviderKey, CancellationToken>((_, assertion, _, _) => observedAssertion = assertion)
            .ReturnsAsync(RateLimitDecision.Allow());
        var service = CreateService(limiter.Object);
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalAssertionAsync(httpContext, " Missing ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.UnsupportedProvider));
            Assert.That(observedAssertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey((ProviderType)"EXTERNAL_UNSUPPORTED", "Missing")));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }

        limiter.VerifyAll();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnRateLimitedWhenUnsupportedProviderIsRateLimited()
    {
        var limiter = CreateBlockedLimiter();
        var events = new RecordingSecurityEventSink();
        var service = CreateService(limiter.Object, securityEventSink: events);
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Missing");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.RateLimited));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
            Assert.That(events.Events, Has.Count.EqualTo(1));
            Assert.That(events.Events[0].EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(events.Events[0].FailureReason, Is.EqualTo(SecurityEventFailureReasons.RateLimited));
            Assert.That(events.Events[0].Provider, Is.EqualTo(new AuthenticationProviderKey((ProviderType)"EXTERNAL_UNSUPPORTED", "Missing")));
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldAllowMissingSecurityEventSinkWhenRateLimited()
    {
        var options = new AshlarOAuthOptions();
        options.AddGoogle();
        var service = new AshlarExternalCredentialAuthenticationService(
            CreateBlockedLimiter().Object,
            new TestOptionsMonitor(options));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Missing");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.RateLimited));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldReturnRateLimitedWhenProviderMismatchIsRateLimited()
    {
        var limiter = CreateBlockedLimiter();
        var events = new RecordingSecurityEventSink();
        var service = CreateService(limiter.Object, securityEventSink: events);
        var httpContext = CreateHttpContextWithExternalTicket("Microsoft", "Microsoft", "subject");

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.RateLimited));
            Assert.That(events.Events, Has.Count.EqualTo(1));
            Assert.That(events.Events[0].EventType, Is.EqualTo(AshlarSecurityEventTypes.AuthenticationRateLimited));
            Assert.That(events.Events[0].Provider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldIgnoreCleanupFailureForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), signOutException: new InvalidOperationException("cleanup failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalAssertionAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteExternalAssertionShouldClearExternalTicketWhenAuthenticateThrows()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), new InvalidOperationException("auth failed"));
        var httpContext = CreateHttpContext(authService);

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteExternalAssertionAsync(httpContext, "Google"));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    [Test]
    public void CompleteExternalAssertionShouldRejectNullHttpContext()
    {
        var service = CreateService(new AuthenticationResponse(false));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteExternalAssertionAsync(null!, "Google"));
    }

    [Test]
    public void ConstructorShouldRejectRequiredNullDependenciesAndAcceptOptionalDependencies()
    {
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>().Object;
        var options = new TestOptionsMonitor(new AshlarOAuthOptions());
        var events = new NullSecurityEventSink();
        var timeProvider = TimeProvider.System;

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalCredentialAuthenticationService(null!, options, events, timeProvider));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalCredentialAuthenticationService(limiter, null!, events, timeProvider));
            Assert.DoesNotThrow(() => new AshlarExternalCredentialAuthenticationService(limiter, options, null, timeProvider));
            Assert.DoesNotThrow(() => new AshlarExternalCredentialAuthenticationService(limiter, options, events, null));
            Assert.DoesNotThrow(() => new AshlarExternalCredentialAuthenticationService(limiter, options));
        }
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(AuthenticationResponse response, bool includeGitHub = false)
    {
        return CreateService(response, includeGitHub ? options => options.AddGitHub() : null);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(AuthenticationResponse response, Action<AshlarOAuthOptions>? configureOptions)
    {
        _ = response;
        return CreateService(CreateAllowingLimiter().Object, configureOptions);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(IPrimaryAuthenticationRateLimiter limiter, bool includeGitHub = false)
    {
        return CreateServiceCore(limiter, includeGitHub ? options => options.AddGitHub() : null, null);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(IPrimaryAuthenticationRateLimiter limiter, Action<AshlarOAuthOptions>? configureOptions)
    {
        return CreateServiceCore(limiter, configureOptions, null);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(IPrimaryAuthenticationRateLimiter limiter, ISecurityEventSink? securityEventSink)
    {
        return CreateServiceCore(limiter, null, securityEventSink);
    }

    private static AshlarExternalCredentialAuthenticationService CreateServiceCore(
        IPrimaryAuthenticationRateLimiter limiter,
        Action<AshlarOAuthOptions>? configureOptions,
        ISecurityEventSink? securityEventSink)
    {
        var options = new AshlarOAuthOptions();
        options.AddGoogle();
        configureOptions?.Invoke(options);

        var monitor = new TestOptionsMonitor(options);
        return new AshlarExternalCredentialAuthenticationService(limiter, monitor, securityEventSink ?? new NullSecurityEventSink(), TimeProvider.System);
    }

    private static AshlarExternalCredentialAuthenticationService CreateServiceWithProvider(AshlarOidcProviderOptions provider)
    {
        return CreateServiceWithProvider(provider, CreateAllowingLimiter().Object);
    }

    private static AshlarExternalCredentialAuthenticationService CreateServiceWithProvider(AshlarOidcProviderOptions provider, IPrimaryAuthenticationRateLimiter limiter)
    {
        var options = new AshlarOAuthOptions();
        var providers = (Dictionary<string, AshlarOidcProviderOptions>)typeof(AshlarOAuthOptions)
            .GetField("_oidcProviders", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(options)!;
        providers["Google"] = provider;
        return new AshlarExternalCredentialAuthenticationService(limiter, new TestOptionsMonitor(options), new NullSecurityEventSink(), TimeProvider.System);
    }

    private static Mock<IPrimaryAuthenticationRateLimiter> CreateAllowingLimiter()
    {
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        limiter.Setup(l => l.CheckAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(RateLimitDecision.Allow());
        return limiter;
    }

    private static Mock<IPrimaryAuthenticationRateLimiter> CreateBlockedLimiter()
    {
        var limiter = new Mock<IPrimaryAuthenticationRateLimiter>();
        limiter.Setup(l => l.CheckAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<AuthenticationProviderKey>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RateLimitDecision
            {
                Status = RateLimitStatus.Blocked,
                Remaining = 0,
                WindowResetAt = DateTimeOffset.UtcNow.AddMinutes(1),
                RetryAfter = DateTimeOffset.UtcNow.AddMinutes(1)
            });
        return limiter;
    }

    private static ClaimsPrincipal CreatePrincipal(string subject)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject), new Claim("email", "person@example.com")], "oidc"));
    }

    private static ClaimsPrincipal CreateGitHubPrincipal(string id)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", id), new Claim("login", "octocat"), new Claim("email", "octo@example.com")], "oauth"));
    }

    private static DefaultHttpContext CreateHttpContextWithExternalTicket(string providerName, string schemeName, string subject)
    {
        return CreateHttpContextWithExternalTicket(providerName, schemeName, ProviderType.Oidc, CreatePrincipal(subject));
    }

    private static DefaultHttpContext CreateHttpContextWithExternalTicket(string providerName, string schemeName, ProviderType providerType, ClaimsPrincipal principal)
    {
        return CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                principal,
                CreateProperties(providerName, schemeName, providerType),
                "Ashlar.OAuth.External"))));
    }

    private static DefaultHttpContext CreateHttpContext(IAuthenticationService authenticationService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(authenticationService);
        return new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
    }

    private static AuthenticationProperties CreateProperties(string providerName, string schemeName, ProviderType? providerType = null, bool includeProviderType = true)
    {
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = providerName;
        properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = schemeName;
        if (includeProviderType)
        {
            properties.Items[AshlarOAuthAuthenticationProperties.ProviderType] = (providerType ?? ProviderType.Oidc).Value;
        }

        return properties;
    }

    private sealed class TestOptionsMonitor(AshlarOAuthOptions options) : Microsoft.Extensions.Options.IOptionsMonitor<AshlarOAuthOptions>
    {
        public AshlarOAuthOptions CurrentValue => options;
        public AshlarOAuthOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<AshlarOAuthOptions, string?> listener) => null;
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

    private sealed class TestAuthenticationService(AuthenticateResult result, Exception? authenticateException = null, Exception? signOutException = null) : IAuthenticationService
    {
        public int SignOutCount { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            if (authenticateException != null)
            {
                throw authenticateException;
            }

            return Task.FromResult(result);
        }

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            return Task.CompletedTask;
        }

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            return Task.CompletedTask;
        }

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            return Task.CompletedTask;
        }

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOutCount++;
            if (signOutException != null)
            {
                throw signOutException;
            }

            return Task.CompletedTask;
        }
    }
}
