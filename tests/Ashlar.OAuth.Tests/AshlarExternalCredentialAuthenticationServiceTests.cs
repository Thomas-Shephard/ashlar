using System.Security.Claims;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Providers.External;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarExternalCredentialAuthenticationServiceTests
{
    [Test]
    public async Task CompleteOidcCredentialAuthenticationShouldReturnUnsupportedProviderForMissingProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));

        var result = await service.CompleteOidcCredentialAuthenticationAsync("Missing", CreatePrincipal("sub"), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(false));

        var result = await service.CompleteOidcCredentialAuthenticationAsync("Google", new ClaimsPrincipal(new ClaimsIdentity()), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));

        var result = await service.CompleteOidcCredentialAuthenticationAsync("Google", CreatePrincipal("subject"), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public void CompleteOidcCredentialAuthenticationShouldRejectNullPrincipal()
    {
        var service = CreateService(new AuthenticationResponse(false));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteOidcCredentialAuthenticationAsync("Google", null!, new AuthenticationContext()));
    }

    [TestCase(AuthenticationStatus.Success, true, AshlarExternalCredentialAuthenticationStatus.Succeeded)]
    [TestCase(AuthenticationStatus.Failed, false, AshlarExternalCredentialAuthenticationStatus.AshlarAuthenticationFailed)]
    [TestCase(AuthenticationStatus.Disabled, false, AshlarExternalCredentialAuthenticationStatus.Disabled)]
    [TestCase(AuthenticationStatus.MfaRequired, false, AshlarExternalCredentialAuthenticationStatus.MfaRequired)]
    public async Task CompleteOidcCredentialAuthenticationShouldMapAshlarResponseStatus(
        AuthenticationStatus authenticationStatus,
        bool succeeded,
        AshlarExternalCredentialAuthenticationStatus expectedStatus)
    {
        var response = new AuthenticationResponse(succeeded, Status: authenticationStatus);
        var service = CreateService(response);

        var result = await service.CompleteOidcCredentialAuthenticationAsync("Google", CreatePrincipal("subject"), new AuthenticationContext(TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(expectedStatus));
            Assert.That(result.Authentication, Is.SameAs(response));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }
    }

    [TestCase(AshlarExternalAssertionStatus.AuthenticationFailed, AshlarExternalCredentialAuthenticationStatus.AuthenticationFailed)]
    [TestCase(AshlarExternalAssertionStatus.UnsupportedProvider, AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider)]
    [TestCase(AshlarExternalAssertionStatus.InvalidPrincipal, AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal)]
    [TestCase(AshlarExternalAssertionStatus.ProviderMismatch, AshlarExternalCredentialAuthenticationStatus.ProviderMismatch)]
    [TestCase(AshlarExternalAssertionStatus.Unknown, AshlarExternalCredentialAuthenticationStatus.Unknown)]
    [TestCase(AshlarExternalAssertionStatus.Succeeded, AshlarExternalCredentialAuthenticationStatus.Unknown)]
    public void MapAssertionStatusShouldMapAssertionFailuresAndDefensiveFallbacks(
        AshlarExternalAssertionStatus assertionStatus,
        AshlarExternalCredentialAuthenticationStatus expectedStatus)
    {
        var method = typeof(AshlarExternalCredentialAuthenticationService).GetMethod(
            "MapAssertionStatus",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        var status = method?.Invoke(null, [assertionStatus]);

        Assert.That(status, Is.EqualTo(expectedStatus));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationShouldPassTenantAwareContextToPipeline()
    {
        var tenantId = Guid.NewGuid();
        AuthenticationContext? observedContext = null;
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, CancellationToken>((context, _, _) => observedContext = context)
            .ReturnsAsync(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));

        var service = CreateService(pipeline.Object);

        await service.CompleteOidcCredentialAuthenticationAsync("Google", CreatePrincipal("subject"), new AuthenticationContext(TenantId: tenantId));

        Assert.That(observedContext?.TenantId, Is.EqualTo(tenantId));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldRejectMismatchedExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Microsoft", "Microsoft", "subject");

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnUnsupportedProviderForBlankProviderName()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, " ");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldClearExternalTicketForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldIgnoreCleanupFailureForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), signOutException: new InvalidOperationException("cleanup failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnAuthenticationFailedWhenExternalAuthenticateFails()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.Fail("failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.AuthenticationFailed));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteOidcCredentialAuthenticationFromHttpContextShouldClearExternalTicketWhenAuthenticateThrows()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), new InvalidOperationException("auth failed"));
        var httpContext = CreateHttpContext(authService);

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google"));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnInvalidPrincipalWhenPrincipalHasNoClaims()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(), CreateProperties("Google", "Google"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnProviderMismatchWhenTicketPropertiesAreMissing()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("subject"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnProviderMismatchWhenTicketSchemeIsMissing()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = "Google";
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("subject"), properties, "Ashlar.OAuth.External"))));

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([], "oidc")), CreateProperties("Google", "Google"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));
        var httpContext = CreateHttpContextWithExternalTicket(" ", "Google", "subject");

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldAcceptMatchingExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.Succeeded));
    }

    [Test]
    public async Task CompleteOidcAssertionShouldMapMatchingExternalTicketWithoutCallingAuthenticationPipeline()
    {
        var pipeline = new Mock<IAuthenticationPipeline>(MockBehavior.Strict);
        var service = CreateService(pipeline.Object);
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteOidcAssertionAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }

        pipeline.VerifyNoOtherCalls();
    }

    [Test]
    public async Task CompleteOidcAssertionShouldLeaveSessionIssuanceToHostOrchestration()
    {
        var pipeline = new Mock<IAuthenticationPipeline>(MockBehavior.Strict);
        var orchestrator = new Mock<IAuthenticationOrchestrator>(MockBehavior.Strict);
        var service = CreateService(pipeline.Object);
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

        var assertionResult = await service.CompleteOidcAssertionAsync(httpContext, "Google");
        var authentication = await orchestrator.Object.AuthenticateAsync(new AuthenticationContext(), assertionResult.Assertion!, cancellationToken: CancellationToken.None);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertionResult.Succeeded, Is.True);
            Assert.That(authentication.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(authentication.User, Is.SameAs(user.Object));
            Assert.That(observedProvider, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
        }

        pipeline.VerifyNoOtherCalls();
        orchestrator.VerifyAll();
    }

    [Test]
    public async Task CompleteOidcAssertionShouldReturnProviderMismatchForMismatchedExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Microsoft", "Microsoft", "subject");

        var result = await service.CompleteOidcAssertionAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));
            Assert.That(result.Succeeded, Is.False);
        }
    }

    [Test]
    public async Task CompleteOidcAssertionShouldReturnAuthenticationFailedForFailedTicket()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContext(new TestAuthenticationService(AuthenticateResult.Fail("failed")));

        var result = await service.CompleteOidcAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.AuthenticationFailed));
    }

    [Test]
    public async Task CompleteOidcAssertionShouldReturnProviderMismatchWhenTicketPropertiesAreMissing()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("subject"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteOidcAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteOidcAssertionShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity([], "oidc")),
                CreateProperties("Google", "Google"),
                "Ashlar.OAuth.External"))));

        var result = await service.CompleteOidcAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteOidcAssertionShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));
        var httpContext = CreateHttpContextWithExternalTicket(" ", "Google", "subject");

        var result = await service.CompleteOidcAssertionAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteOidcAssertionShouldClearExternalTicketForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteOidcAssertionAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteOidcAssertionShouldRejectNullHttpContext()
    {
        var service = CreateService(new AuthenticationResponse(false));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteOidcAssertionAsync(null!, "Google"));
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldNotFailWhenCleanupFailsAfterSuccessfulAuthentication()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var authService = new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreatePrincipal("subject"),
                CreateProperties("Google", "Google"),
                "Ashlar.OAuth.External")),
            signOutException: new InvalidOperationException("cleanup failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.Succeeded));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteOidcCredentialAuthenticationFromHttpContextShouldPopulateAuthenticationContextFromHttpContext()
    {
        AuthenticationContext? observedContext = null;
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, CancellationToken>((context, _, _) => observedContext = context)
            .ReturnsAsync(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var service = CreateService(pipeline.Object);
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        httpContext.Request.Headers.UserAgent = "test-agent";
        httpContext.TraceIdentifier = "trace-123";
        var tenantId = Guid.NewGuid();

        await service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google", tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(observedContext?.TenantId, Is.EqualTo(tenantId));
            Assert.That(observedContext?.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(observedContext?.UserAgent, Is.EqualTo("test-agent"));
            Assert.That(observedContext?.CorrelationId, Is.EqualTo("trace-123"));
        }
    }

    [Test]
    public void CompleteOidcCredentialAuthenticationFromHttpContextShouldClearExternalTicketBeforePipelineFailure()
    {
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("pipeline failed"));

        var authService = new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreatePrincipal("subject"),
                CreateProperties("Google", "Google"),
                "Ashlar.OAuth.External")));
        var service = CreateService(pipeline.Object);
        var httpContext = CreateHttpContext(authService);

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteOidcCredentialAuthenticationAsync(httpContext, "Google"));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    [Test]
    public void ConstructorShouldRejectNullDependencies()
    {
        var pipeline = new Mock<IAuthenticationPipeline>().Object;
        var options = new TestOptionsMonitor(new AshlarOAuthOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalCredentialAuthenticationService(null!, options));
            Assert.Throws<ArgumentNullException>(() => new AshlarExternalCredentialAuthenticationService(pipeline, null!));
        }
    }

    [Test]
    public void ResultSucceededShouldReflectStatus()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(new AshlarExternalCredentialAuthenticationResult(AshlarExternalCredentialAuthenticationStatus.Succeeded).Succeeded, Is.True);
            Assert.That(new AshlarExternalCredentialAuthenticationResult(AshlarExternalCredentialAuthenticationStatus.AuthenticationFailed).Succeeded, Is.False);
        }
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(AuthenticationResponse response)
    {
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        return CreateService(pipeline.Object);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(IAuthenticationPipeline pipeline)
    {
        var options = new AshlarOAuthOptions();
        options.AddOidcProvider("Google", _ => { });
        var monitor = new TestOptionsMonitor(options);
        return new AshlarExternalCredentialAuthenticationService(pipeline, monitor);
    }

    private static AshlarExternalCredentialAuthenticationService CreateServiceWithProvider(AshlarOidcProviderOptions provider)
    {
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var options = new AshlarOAuthOptions();
        var providers = (Dictionary<string, AshlarOidcProviderOptions>)typeof(AshlarOAuthOptions)
            .GetField("_oidcProviders", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(options)!;
        providers["Google"] = provider;
        return new AshlarExternalCredentialAuthenticationService(pipeline.Object, new TestOptionsMonitor(options));
    }

    private static ClaimsPrincipal CreatePrincipal(string subject)
    {
        return new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject), new Claim("email", "person@example.com")], "oidc"));
    }

    private static DefaultHttpContext CreateHttpContextWithExternalTicket(string providerName, string schemeName, string subject)
    {
        return CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreatePrincipal(subject),
                CreateProperties(providerName, schemeName),
                "Ashlar.OAuth.External"))));
    }

    private static DefaultHttpContext CreateHttpContext(IAuthenticationService authenticationService)
    {
        var services = new ServiceCollection();
        services.AddSingleton(authenticationService);
        return new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
    }

    private static AuthenticationProperties CreateProperties(string providerName, string schemeName)
    {
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = providerName;
        properties.Items[AshlarOAuthAuthenticationProperties.SchemeName] = schemeName;
        return properties;
    }

    private sealed class TestOptionsMonitor(AshlarOAuthOptions options) : Microsoft.Extensions.Options.IOptionsMonitor<AshlarOAuthOptions>
    {
        public AshlarOAuthOptions CurrentValue => options;
        public AshlarOAuthOptions Get(string? name) => options;
        public IDisposable? OnChange(Action<AshlarOAuthOptions, string?> listener) => null;
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
