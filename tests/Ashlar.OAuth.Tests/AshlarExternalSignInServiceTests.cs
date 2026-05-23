using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarExternalSignInServiceTests
{
    [Test]
    public async Task CompleteOidcSignInShouldReturnUnsupportedProviderForMissingProvider()
    {
        var service = CreateService(new AuthenticationResponse(false));

        var result = await service.CompleteOidcSignInAsync("Missing", CreatePrincipal("sub"), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalSignInStatus.UnsupportedProvider));
    }

    [Test]
    public async Task CompleteOidcSignInShouldReturnInvalidPrincipalForMissingSubject()
    {
        var service = CreateService(new AuthenticationResponse(false));

        var result = await service.CompleteOidcSignInAsync("Google", new ClaimsPrincipal(new ClaimsIdentity()), new AuthenticationContext());

        Assert.That(result.Status, Is.EqualTo(AshlarExternalSignInStatus.InvalidPrincipal));
    }

    [Test]
    public void CompleteOidcSignInShouldRejectNullPrincipal()
    {
        var service = CreateService(new AuthenticationResponse(false));

        Assert.ThrowsAsync<ArgumentNullException>(() => service.CompleteOidcSignInAsync("Google", null!, new AuthenticationContext()));
    }

    [TestCase(AuthenticationStatus.Success, true, AshlarExternalSignInStatus.Succeeded)]
    [TestCase(AuthenticationStatus.Failed, false, AshlarExternalSignInStatus.AshlarAuthenticationFailed)]
    [TestCase(AuthenticationStatus.Disabled, false, AshlarExternalSignInStatus.Disabled)]
    [TestCase(AuthenticationStatus.MfaRequired, false, AshlarExternalSignInStatus.MfaRequired)]
    public async Task CompleteOidcSignInShouldMapAshlarResponseStatus(
        AuthenticationStatus authenticationStatus,
        bool succeeded,
        AshlarExternalSignInStatus expectedStatus)
    {
        var response = new AuthenticationResponse(succeeded, Status: authenticationStatus);
        var service = CreateService(response);

        var result = await service.CompleteOidcSignInAsync("Google", CreatePrincipal("subject"), new AuthenticationContext(TenantId: Guid.NewGuid()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(expectedStatus));
            Assert.That(result.Authentication, Is.SameAs(response));
            Assert.That(result.Assertion?.ProviderKey, Is.EqualTo("subject"));
        }
    }

    [Test]
    public async Task CompleteOidcSignInShouldPassTenantAwareContextToPipeline()
    {
        var tenantId = Guid.NewGuid();
        AuthenticationContext? observedContext = null;
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .Callback<AuthenticationContext, IAuthenticationAssertion, CancellationToken>((context, _, _) => observedContext = context)
            .ReturnsAsync(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));

        var service = CreateService(pipeline.Object);

        await service.CompleteOidcSignInAsync("Google", CreatePrincipal("subject"), new AuthenticationContext(TenantId: tenantId));

        Assert.That(observedContext?.TenantId, Is.EqualTo(tenantId));
    }

    [Test]
    public async Task CompleteOidcSignInFromHttpContextShouldRejectMismatchedExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Microsoft", "Microsoft", "subject");

        var result = await service.CompleteOidcSignInAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalSignInStatus.ProviderMismatch));
    }

    [Test]
    public async Task CompleteOidcSignInFromHttpContextShouldAcceptMatchingExternalTicketProvider()
    {
        var service = CreateService(new AuthenticationResponse(true, Status: AuthenticationStatus.Success));
        var httpContext = CreateHttpContextWithExternalTicket("Google", "Google", "subject");

        var result = await service.CompleteOidcSignInAsync(httpContext, "Google");

        Assert.That(result.Status, Is.EqualTo(AshlarExternalSignInStatus.Succeeded));
    }

    [Test]
    public void CompleteOidcSignInFromHttpContextShouldClearExternalTicketBeforePipelineFailure()
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

        Assert.ThrowsAsync<InvalidOperationException>(() => service.CompleteOidcSignInAsync(httpContext, "Google"));
        Assert.That(authService.SignOutCount, Is.EqualTo(1));
    }

    private static AshlarExternalSignInService CreateService(AuthenticationResponse response)
    {
        var pipeline = new Mock<IAuthenticationPipeline>();
        pipeline.Setup(p => p.LoginAsync(It.IsAny<AuthenticationContext>(), It.IsAny<IAuthenticationAssertion>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(response);
        return CreateService(pipeline.Object);
    }

    private static AshlarExternalSignInService CreateService(IAuthenticationPipeline pipeline)
    {
        var options = new AshlarOAuthOptions();
        options.AddOidcProvider("Google", _ => { });
        var monitor = new TestOptionsMonitor(options);
        return new AshlarExternalSignInService(pipeline, monitor);
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

    private sealed class TestAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public int SignOutCount { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
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
            return Task.CompletedTask;
        }
    }
}
