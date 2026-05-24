using System.Security.Claims;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Providers.External;
using Ashlar.OAuth.Providers.GitHub;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarExternalCredentialAuthenticationServiceTests
{
    [Test]
    public async Task CompleteExternalCredentialAuthenticationShouldReturnUnsupportedProviderForMissingProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));

        var result = await service.CompleteExternalCredentialAuthenticationAsync("Missing", CreatePrincipal("sub"), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(false));

        var result = await service.CompleteExternalCredentialAuthenticationAsync("Google", new ClaimsPrincipal(new ClaimsIdentity()), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));

        var result = await service.CompleteExternalCredentialAuthenticationAsync("Google", CreatePrincipal("subject"), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public void CompleteExternalCredentialAuthenticationShouldRejectNullPrincipal()
    {
        var service = CreateService(new AuthenticationResponse(false));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteExternalCredentialAuthenticationAsync("Google", null!, new AuthenticationContext()));
    }

    [TestCase(AuthenticationStatus.Success, true, AshlarExternalCredentialAuthenticationStatus.Succeeded)]
    [TestCase(AuthenticationStatus.Failed, false, AshlarExternalCredentialAuthenticationStatus.AshlarAuthenticationFailed)]
    [TestCase(AuthenticationStatus.Disabled, false, AshlarExternalCredentialAuthenticationStatus.Disabled)]
    [TestCase(AuthenticationStatus.MfaRequired, false, AshlarExternalCredentialAuthenticationStatus.MfaRequired)]
    public async Task CompleteExternalCredentialAuthenticationShouldMapAshlarResponseStatus(
        AuthenticationStatus authenticationStatus,
        bool succeeded,
        AshlarExternalCredentialAuthenticationStatus expectedStatus)
    {
        var response = new AuthenticationResponse(succeeded, Status: authenticationStatus);
        var service = CreateService(response);

        var result = await service.CompleteExternalCredentialAuthenticationAsync("Google", CreatePrincipal("subject"), new AuthenticationContext(TenantId: Guid.NewGuid()));

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
    public async Task CompleteExternalCredentialAuthenticationShouldPassTenantAwareContextToPipeline()
    {
        var tenantId = Guid.NewGuid();
        AuthenticationContext? observedContext = null;
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, CancellationToken>((context, _, _) => observedContext = context)
            .ReturnsAsync(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));

        var service = CreateService(pipeline.Object);

        await service.CompleteExternalCredentialAuthenticationAsync("Google", CreatePrincipal("subject"), new AuthenticationContext(TenantId: tenantId));

        Assert.That(observedContext?.TenantId, Is.EqualTo(tenantId));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldRejectMismatchedExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Microsoft", "Microsoft", "subject");

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnUnsupportedProviderForBlankProviderName()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, " ");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldClearExternalTicketForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult());
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldIgnoreCleanupFailureForUnsupportedProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), signOutException: new InvalidOperationException("cleanup failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, " ");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.UnsupportedProvider));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnAuthenticationFailedWhenExternalAuthenticateFails()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.Fail("failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.AuthenticationFailed));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void CompleteExternalCredentialAuthenticationFromHttpContextShouldClearExternalTicketWhenAuthenticateThrows()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var authService = new TestAuthenticationService(AuthenticateResult.NoResult(), new InvalidOperationException("auth failed"));
        var httpContext = CreateHttpContext(authService);

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google"));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnInvalidPrincipalWhenPrincipalHasNoClaims()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(), CreateProperties("Google", "Google"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnProviderMismatchWhenTicketPropertiesAreMissing()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("subject"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnProviderMismatchWhenTicketSchemeIsMissing()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var properties = new AuthenticationProperties();
        properties.Items[AshlarOAuthAuthenticationProperties.ProviderName] = "Google";
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(CreatePrincipal("subject"), properties, "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(false));
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([], "oidc")), CreateProperties("Google", "Google"), "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldReturnInvalidPrincipalWhenConfiguredProviderNameIsInvalid()
    {
        var service = CreateServiceWithProvider(new AshlarOidcProviderOptions(" ", "Google", _ => { }));
        var httpContext = CreateHttpContextWithExternalTicket(" ", "Google", "subject");

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.InvalidPrincipal));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldAcceptMatchingExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.Succeeded));
    }

    [Test]
    public async Task CompleteExternalAssertionShouldMapMatchingExternalTicketWithoutCallingAuthenticationPipeline()
    {
        var pipeline = new Mock<IAuthenticationPipeline>(MockBehavior.Strict);
        var service = CreateService(pipeline.Object);
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

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
    public async Task CompleteExternalAssertionShouldAcceptLegacyExternalTicketWithoutProviderType()
    {
        var pipeline = new Mock<IAuthenticationPipeline>(MockBehavior.Strict);
        var service = CreateService(pipeline.Object);
        var httpContext = CreateHttpContext(new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreatePrincipal("subject"),
                CreateProperties("Google", "Google", includeProviderType: false),
                "Ashlar.OAuth.External"))));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }

        pipeline.VerifyNoOtherCalls();
    }

    [Test]
    public async Task CompleteExternalAssertionShouldMapGitHubTicketAsOAuthAssertion()
    {
        var pipeline = new Mock<IAuthenticationPipeline>(MockBehavior.Strict);
        var service = CreateService(pipeline.Object, includeGitHub: true);
        var httpContext = CreateHttpContextWithExternalTicket("GitHub", "GitHub", ProviderType.OAuth, CreateGitHubPrincipal("12345"));

        var result = await service.CompleteExternalAssertionAsync(httpContext, "GitHub");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalAssertionStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("12345"));
            Assert.That(result.Assertion?.Claims["login"], Is.EqualTo(["octocat"]));
        }

        pipeline.VerifyNoOtherCalls();
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
    public async Task CompleteExternalCredentialAuthenticationShouldAuthenticateGitHubAssertion()
    {
        var response = new AuthenticationResponse(true, Status: AuthenticationStatus.Success);
        var service = CreateService(response, includeGitHub: true);

        var result = await service.CompleteExternalCredentialAuthenticationAsync("GitHub", CreateGitHubPrincipal("12345"), new AuthenticationContext());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("12345"));
        }
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationShouldUseConfiguredOAuth2ProviderKeyClaim()
    {
        var response = new AuthenticationResponse(true, Status: AuthenticationStatus.Success);
        var service = CreateService(response, options => options.AddOAuth2Provider("CustomOAuth", "uid", _ => { }));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("uid", "stable-uid"), new Claim("id", "not-used")], "oauth"));

        var result = await service.CompleteExternalCredentialAuthenticationAsync("CustomOAuth", principal, new AuthenticationContext());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.Succeeded));
            Assert.That(result.Assertion?.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "CustomOAuth")));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("stable-uid"));
        }
    }

    [Test]
    public async Task CompleteExternalAssertionShouldLeaveSessionIssuanceToHostOrchestration()
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

        var assertionResult = await service.CompleteExternalAssertionAsync(httpContext, "Google");
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
    public void CompleteExternalAssertionShouldRejectNullHttpContext()
    {
        var service = CreateService(new AuthenticationResponse(false));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteExternalAssertionAsync(null!, "Google"));
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldNotFailWhenCleanupFailsAfterSuccessfulAuthentication()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var authService = new TestAuthenticationService(
            AuthenticateResult.Success(new AuthenticationTicket(
                CreatePrincipal("subject"),
                CreateProperties("Google", "Google"),
                "Ashlar.OAuth.External")),
            signOutException: new InvalidOperationException("cleanup failed"));
        var httpContext = CreateHttpContext(authService);

        var result = await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarExternalCredentialAuthenticationStatus.Succeeded));
            Assert.That(authService.SignOutCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CompleteExternalCredentialAuthenticationFromHttpContextShouldPopulateAuthenticationContextFromHttpContext()
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

        await service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google", tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(observedContext?.TenantId, Is.EqualTo(tenantId));
            Assert.That(observedContext?.IpAddress, Is.EqualTo("127.0.0.1"));
            Assert.That(observedContext?.UserAgent, Is.EqualTo("test-agent"));
            Assert.That(observedContext?.CorrelationId, Is.EqualTo("trace-123"));
        }
    }

    [Test]
    public void CompleteExternalCredentialAuthenticationFromHttpContextShouldClearExternalTicketBeforePipelineFailure()
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

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteExternalCredentialAuthenticationAsync(httpContext, "Google"));
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

    private static AshlarExternalCredentialAuthenticationService CreateService(AuthenticationResponse response, bool includeGitHub = false)
    {
        return CreateService(response, includeGitHub ? options => options.AddGitHub() : null);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(AuthenticationResponse response, Action<AshlarOAuthOptions>? configureOptions)
    {
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        return CreateService(pipeline.Object, configureOptions);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(IAuthenticationPipeline pipeline, bool includeGitHub = false)
    {
        return CreateService(pipeline, includeGitHub ? options => options.AddGitHub() : null);
    }

    private static AshlarExternalCredentialAuthenticationService CreateService(IAuthenticationPipeline pipeline, Action<AshlarOAuthOptions>? configureOptions)
    {
        var options = new AshlarOAuthOptions();
        options.AddOidcProvider("Google", _ => { });
        configureOptions?.Invoke(options);

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
