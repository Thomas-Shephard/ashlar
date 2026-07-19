using System.Security.Claims;
using Ashlar.Messaging;
using Ashlar.OAuth;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.OAuth;

internal sealed class PostgresOidcInvitationRegistrationAtomicityTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 3, 12, 0, 0, TimeSpan.Zero);
    private const string ProviderNameProperty = ".ashlar.oauth.providerName";
    private const string SchemeNameProperty = ".ashlar.oauth.schemeName";
    private const string ProviderTypeProperty = ".ashlar.oauth.providerType";

    private PostgresContractDatabaseLease? _database;

    [TearDown]
    public async Task TearDown()
    {
        if (_database != null)
        {
            await _database.DropDatabaseAsync();
            _database = null;
        }
    }

    [Test]
    public async Task RegisterShouldRollBackInvitationAcceptanceAndNewUserWhenOidcCredentialIsLinkedToAnotherUser()
    {
        const string token = "known-invitation-token";
        const string inviteeEmail = "invitee@example.com";
        const string existingEmail = "existing@example.com";
        const string subject = "oidc-subject";
        const string retrySubject = "oidc-retry-subject";
        var existingUserId = Guid.NewGuid();

        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(ConfigureServices);
        await using var scope = _database.ServiceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;

        await SeedInvitationAsync(services, token, inviteeEmail);
        await SeedExistingLinkedCredentialAsync(services, existingUserId, existingEmail, subject);

        var invitations = services.GetRequiredService<IInvitationRepository>();
        var users = services.GetRequiredService<IUserRepository>();
        var credentials = services.GetRequiredService<ICredentialRepository>();
        var service = services.GetRequiredService<AshlarOidcInvitationRegistrationService>();
        var result = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(services, CreateTicket(subject, inviteeEmail)), token, "Google", "Invitee");

        var rolledBackInvitation = await invitations.GetInvitationByTokenHashAsync(services.GetRequiredService<ISecureTokenHasher>().HashToken(token));
        var rolledBackInvitee = await users.GetUserByEmailAsync(inviteeEmail);

        var retryResult = await service.CompleteOidcInvitationRegistrationAsync(CreateHttpContext(services, CreateTicket(retrySubject, inviteeEmail)), token, "Google", "Invitee");

        var invitation = await invitations.GetInvitationByTokenHashAsync(services.GetRequiredService<ISecureTokenHasher>().HashToken(token));
        var invitee = await users.GetUserByEmailAsync(inviteeEmail);
        var existingCredential = await credentials.GetCredentialForUserAsync(existingUserId, ProviderType.Oidc, "Google", CreateProviderKey(subject));
        var retryCredential = await credentials.GetCredentialForUserAsync(retryResult.UserId ?? Guid.Empty, ProviderType.Oidc, "Google", CreateProviderKey(retrySubject));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.AlreadyLinkedToAnotherUser));
            Assert.That(rolledBackInvitation, Is.Not.Null);
            Assert.That(rolledBackInvitation!.AcceptedAt, Is.Null);
            Assert.That(rolledBackInvitee, Is.Null);
            Assert.That(retryResult.Status, Is.EqualTo(AshlarOidcInvitationRegistrationStatus.Registered));
            Assert.That(invitation, Is.Not.Null);
            Assert.That(invitation!.AcceptedAt, Is.Not.Null);
            Assert.That(invitee, Is.Not.Null);
            Assert.That(existingCredential, Is.Not.Null);
            Assert.That(retryCredential, Is.Not.Null);
        }
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<ISecretProtector, TestSecretProtector>();
        services.Replace(ServiceDescriptor.Singleton<IEmailSender, NullEmailSender>());
        services.AddAshlarOAuth(options => options.AddOidcProvider("Google", oidc =>
        {
            oidc.Authority = "https://accounts.example";
            oidc.ClientId = "client";
        }));
    }

    private static async Task SeedInvitationAsync(IServiceProvider services, string token, string email)
    {
        await services.GetRequiredService<IInvitationRepository>().CreateInvitationAsync(new UserInvitation
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TokenHash = services.GetRequiredService<ISecureTokenHasher>().HashToken(token),
            CreatedAt = Now,
            UpdatedAt = Now,
            ExpiresAt = Now.AddDays(1),
            Version = Guid.NewGuid().ToString("N")
        });
    }

    private static async Task SeedExistingLinkedCredentialAsync(IServiceProvider services, Guid userId, string email, string subject)
    {
        await services.GetRequiredService<IUserRepository>().CreateUserAsync(new AshlarUser
        {
            Id = userId,
            DisplayEmail = email,
            AccountState = UserAccountState.Active,
            EmailVerifiedAt = Now
        });
        await services.GetRequiredService<ICredentialRepository>().CreateCredentialAsync(new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = CreateProviderKey(subject),
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = Now,
            Status = CredentialStatus.Active
        });
    }

    private static ClaimsPrincipal CreatePrincipal(string subject, string email)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("iss", "https://accounts.example"),
            new Claim("sub", subject),
            new Claim("email", email),
            new Claim("email_verified", "true")
        ], "oidc"));
    }

    private static string CreateProviderKey(string subject) => OidcExternalIdentityAssertionMapper.Map("Google", CreatePrincipal(subject, "unused@example.com")).ProviderKey;

    private static AuthenticateResult CreateTicket(string subject, string email)
    {
        var properties = new AuthenticationProperties();
        properties.Items[ProviderNameProperty] = "Google";
        properties.Items[SchemeNameProperty] = "Google";
        properties.Items[ProviderTypeProperty] = ProviderType.Oidc.Value;

        return AuthenticateResult.Success(new AuthenticationTicket(
            CreatePrincipal(subject, email),
            properties,
            "Ashlar.OAuth.External"));
    }

    private static DefaultHttpContext CreateHttpContext(IServiceProvider services, AuthenticateResult ticket)
    {
        return new DefaultHttpContext
        {
            RequestServices = new AuthenticationServiceProvider(services, new TestAuthenticationService(ticket))
        };
    }

    private sealed class AuthenticationServiceProvider(IServiceProvider inner, IAuthenticationService authenticationService) : IServiceProvider
    {
        public object? GetService(Type serviceType)
        {
            return serviceType == typeof(IAuthenticationService)
                ? authenticationService
                : inner.GetService(serviceType);
        }
    }

    private sealed class TestAuthenticationService(AuthenticateResult result) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
        {
            return Task.FromResult(result);
        }

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }

    private sealed class TestSecretProtector : ISecretProtector
    {
        public string Protect(string plaintext) => plaintext;

        public string Unprotect(string protectedValue) => protectedValue;

        public byte[] Protect(byte[] plaintext) => plaintext;

        public byte[] Unprotect(byte[] protectedValue) => protectedValue;
    }
}
