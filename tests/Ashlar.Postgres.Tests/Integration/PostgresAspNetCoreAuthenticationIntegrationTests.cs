using System.Text.RegularExpressions;
using Ashlar.AspNetCore.Authentication;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Providers.Email;
using Ashlar.Messaging;
using Ashlar.Postgres.Models;
using Dapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Ashlar.Postgres.Tests.Integration;

internal sealed class PostgresAspNetCoreAuthenticationIntegrationTests : PostgresTestBase
{
    private ServiceProvider? _serviceProvider;
    private RecordingEmailSender _emailSender;

    private ServiceProvider ServiceProvider => _serviceProvider ?? throw new InvalidOperationException("The test service provider has not been initialized.");

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        _emailSender = new RecordingEmailSender();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddSingleton<IEmailSender>(_emailSender);
        services.AddSingleton<IAccountSecurityOperationAuthorizer, PermitAccountSecurityOperationAuthorizer>();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddPostgresProviderContractTestServices();
        services.AddAshlarPostgresAuditSink();
        services.AddAshlarDataProtectionSecretProtector();
        services.AddAshlarMagicLinkSignIn();
        services.AddAshlarNoMfaPolicy();
        services.AddAshlarAspNetCoreSessions();
        services.Configure<Ashlar.Identity.Models.Authentication.UriValidationOptions>(o => o.AllowedCallbackUris.Add("https://example.test/sign-in"));

        _serviceProvider = services.BuildServiceProvider();
        await ServiceProvider.InitializeAshlarPostgresSchemaAsync();
    }

    private sealed class PermitAccountSecurityOperationAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(true);
    }

    public override async Task OneTimeTearDown()
    {
        if (_serviceProvider != null)
        {
            await _serviceProvider.DisposeAsync();
        }

        await base.OneTimeTearDown();
    }

    [Test]
    public async Task MagicLinkSignInCreatesPostgresCredentialSessionAndAuthenticatesCookie()
    {
        var user = new AshlarPostgresUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = "magic-e2e@example.com",
            AccountState = UserAccountState.Active,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await using var setupScope = ServiceProvider.CreateAsyncScope();
        await setupScope.ServiceProvider.GetRequiredService<IUserRepository>().CreateUserAsync(user);

        var magicLinks = setupScope.ServiceProvider.GetRequiredService<IMagicLinkSignInService>();
        await magicLinks.RequestLinkAsync(user.DisplayEmail, new Uri("https://example.test/sign-in/callback"));

        var message = _emailSender.Messages.Single();
        var body = message.TextBody ?? throw new AssertionException("Magic-link email should include a text body.");
        var token = ExtractQueryValue(body, "token");
        await using var connection = new NpgsqlConnection(GetConnectionString());
        var (persistedCredentialKey, persistedCredentialValue) = await connection.QuerySingleAsync<(string ProviderKey, string? CredentialValue)>(
            "select provider_key, credential_value from ashlar_credentials where user_id = @UserId",
            new { UserId = user.Id });

        var response = await magicLinks.VerifyLinkAsync(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(response.Status, Is.EqualTo(MfaAuthenticationStatus.Succeeded));
            Assert.That(response.User?.Id, Is.EqualTo(user.Id));
        }

        var signInContext = new DefaultHttpContext { RequestServices = setupScope.ServiceProvider, Request = { Scheme = "https", Host = new HostString("example.test") }, Connection = { RemoteIpAddress = System.Net.IPAddress.Loopback } };
        signInContext.Request.Headers.UserAgent = "Ashlar integration test";

        var session = await setupScope.ServiceProvider.GetRequiredService<IAshlarSignInManager>().SignInAsync(signInContext, response);
        var setCookie = signInContext.Response.Headers.SetCookie.ToString();
        var rawSessionToken = ExtractCookieValue(setCookie, AshlarSessionAuthenticationDefaults.CookieName);

        var authContext = new DefaultHttpContext { RequestServices = setupScope.ServiceProvider, Request = { Scheme = "https", Host = new HostString("example.test"), Headers = { Cookie = $"{AshlarSessionAuthenticationDefaults.CookieName}={rawSessionToken}" } } };

        var authenticateResult = await setupScope.ServiceProvider
                                                 .GetRequiredService<IAuthenticationService>()
                                                 .AuthenticateAsync(authContext, AshlarSessionAuthenticationDefaults.AuthenticationScheme);

        var persistedSessionTokenHash = await connection.QuerySingleAsync<string>(
            "select token_hash from ashlar_sessions where id = @SessionId",
            new { SessionId = session.Id });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(authenticateResult.Succeeded, Is.True);
            Assert.That(authenticateResult.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value, Is.EqualTo(user.Id.ToString("D")));
            Assert.That(setCookie, Does.Contain("httponly").IgnoreCase);
            Assert.That(setCookie, Does.Contain("secure").IgnoreCase);
            Assert.That(setCookie, Does.Contain("samesite=lax").IgnoreCase);
            Assert.That(persistedCredentialKey, Is.Not.EqualTo(token));
            Assert.That(persistedCredentialKey, Does.StartWith("sha256:"));
            Assert.That(persistedCredentialValue, Is.Null);
            Assert.That(persistedSessionTokenHash, Is.Not.EqualTo(rawSessionToken));
            Assert.That(persistedSessionTokenHash, Does.StartWith("sha256:"));
        }
    }

    private static string ExtractQueryValue(string text, string name)
    {
        var match = Regex.Match(text, "[?&]" + Regex.Escape(name) + "=([^&\\s]+)");
        Assert.That(match.Success, Is.True);
        return Uri.UnescapeDataString(match.Groups[1].Value);
    }

    private static string ExtractCookieValue(string setCookie, string name)
    {
        var match = Regex.Match(setCookie, Regex.Escape(name) + "=([^;]+)");
        Assert.That(match.Success, Is.True);
        return match.Groups[1].Value;
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];

        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }
}
