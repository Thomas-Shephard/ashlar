using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.Abstractions.AccountSecurity;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Models.Mfa;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.OAuth;
using Ashlar.OAuth.Providers.GitHub;
using Ashlar.Passkeys;
using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace Ashlar.Postgres.Tests.DependencyInjection;

internal sealed class AshlarPostgresCompositionTests
{
    [Test]
    public void AddAshlarPostgresExplicitConnectionShouldReplaceAmbientDataSource()
    {
        using var ambientDataSource = CreateDataSource("ambient");
        var services = new ServiceCollection();
        services.AddSingleton(ambientDataSource);

        services.AddAshlarPostgres(CreateConnectionString("explicit-main"));
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<NpgsqlDataSource>(), Is.Not.SameAs(ambientDataSource));
    }

    [Test]
    public void AddAshlarPostgresExplicitDataSourceShouldReplaceAmbientDataSource()
    {
        using var ambientDataSource = CreateDataSource("ambient");
        using var explicitDataSource = CreateDataSource("explicit-main");
        var services = new ServiceCollection();
        services.AddSingleton(ambientDataSource);

        services.AddAshlarPostgres(explicitDataSource);
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<NpgsqlDataSource>(), Is.SameAs(explicitDataSource));
    }

    [Test]
    public void AddAshlarPostgresBootstrapExplicitConnectionShouldReplaceAmbientDataSource()
    {
        using var ambientDataSource = CreateDataSource("ambient");
        var services = new ServiceCollection();
        services.AddSingleton(ambientDataSource);

        services.AddAshlarPostgresBootstrap(CreateConnectionString("explicit-bootstrap"));
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<NpgsqlDataSource>(), Is.Not.SameAs(ambientDataSource));
    }

    [Test]
    public void AddAshlarPostgresBootstrapExplicitDataSourceShouldReplaceAmbientDataSource()
    {
        using var ambientDataSource = CreateDataSource("ambient");
        using var explicitDataSource = CreateDataSource("explicit-bootstrap");
        var services = new ServiceCollection();
        services.AddSingleton(ambientDataSource);

        services.AddAshlarPostgresBootstrap(explicitDataSource);
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<NpgsqlDataSource>(), Is.SameAs(explicitDataSource));
    }

    [Test]
    public void AddAshlarPostgresAuthorizationExplicitConnectionShouldReplaceAmbientDataSource()
    {
        using var ambientDataSource = CreateDataSource("ambient");
        var services = new ServiceCollection();
        services.AddSingleton(ambientDataSource);

        services.AddAshlarPostgresAuthorization(CreateConnectionString("explicit-authorization"));
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<NpgsqlDataSource>(), Is.Not.SameAs(ambientDataSource));
    }

    [Test]
    public void AddAshlarPostgresAuthorizationExplicitDataSourceShouldReplaceAmbientDataSource()
    {
        using var ambientDataSource = CreateDataSource("ambient");
        using var explicitDataSource = CreateDataSource("explicit-authorization");
        var services = new ServiceCollection();
        services.AddSingleton(ambientDataSource);

        services.AddAshlarPostgresAuthorization(explicitDataSource);
        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<NpgsqlDataSource>(), Is.SameAs(explicitDataSource));
    }

    [Test]
    public async Task AddAshlarPostgresBroadPackageCompositionBuildsWithStrictValidation()
    {
        using var dataSource = CreateDataSource("sample");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddHttpContextAccessor();
        services.AddDataProtection();
        services.AddAshlarIdentity();
        services.AddPasswordHasher<PasswordHasherV1>();
        services.AddAuthenticationProvider<LocalPasswordProvider>();
        services.AddAshlarPostgres(dataSource);
        services.AddAshlarDataProtectionSecretProtector();
        services.AddAshlarMagicLinkSignIn(options => options.LinkTokenParameterName = "t");
        services.AddAshlarEmailCodeSignIn();
        services.AddAshlarEmailVerification();
        services.AddAshlarEmailChange();
        services.AddAshlarSecurityNotifications();
        services.AddAshlarInvitations();
        services.AddAshlarBootstrap(options =>
        {
            options.SetupSecret = "development-bootstrap-secret";
            options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        });
        services.AddAshlarAuthorization();
        services.AddAshlarRequireMfaWhenCredentialExists(options =>
        {
            options.CredentialProviderKeys.Add(TotpOptions.DefaultProviderKey);
            options.RequiredFactors.Add(AuthenticationFactorTypes.Totp);
        });
        services.AddAshlarTotp();
        services.AddAshlarRecoveryCodes();
        services.AddAshlarPasskeys(options =>
        {
            options.RelyingPartyId = "localhost";
            options.RelyingPartyName = "Ashlar Tests";
            options.Origin = "https://localhost";
        });
        services.AddAshlarOAuth(options => options.AddGitHub(oauth =>
        {
            oauth.ClientId = "client-id";
            oauth.ClientSecret = "client-secret";
        }));
        services.AddAshlarPostgresAuditSink();
        services.AddScoped<IAccountSecurityGuard, TestAccountSecurityGuard>();
        services.AddScoped<IAccountSecurityOperationAuthorizer, TestAccountSecurityOperationAuthorizer>();
        services.AddAshlarPostgresRateLimiting();
        services.AddAshlarPostgresEmailOutboxHostedService<TestEmailTransport>();
        services.AddAshlarPostgresCleanupHostedService();
        services.AddAshlarPostgresSecurityEventWebhookHostedService(configureWebhooks: options =>
        {
            options.Endpoints.Add(new AshlarSecurityEventWebhookEndpointOptions
            {
                Name = "test",
                Uri = new Uri("https://webhooks.example.test/ashlar"),
                SharedSecret = "test-secret"
            });
        });
        services.AddAshlarAspNetCoreSessions();
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfa());
        services.AddHealthChecks().AddAshlarHealthChecks();
        services.AddAshlarSmtpEmailTransport(options =>
        {
            options.Host = "localhost";
            options.DefaultFromAddress = "ashlar@example.test";
        });

        await using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IIdentityService),
            typeof(IBootstrapService),
            typeof(IAuthorizationGrantService),
            typeof(IPasskeyService),
            typeof(AshlarExternalCredentialAuthenticationService),
            typeof(IAshlarCleanupService),
            typeof(IEmailOutboxDispatcher),
            typeof(IAshlarSecurityEventWebhookOutboxOperations),
            typeof(IAuthenticationRateLimiter),
            typeof(IAshlarSchemaDiagnostics),
            typeof(IAshlarOperationsSummaryService));
        await using var scope = provider.CreateAsyncScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IEmailSender>(), Is.TypeOf<PostgresEmailOutboxSender>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.TypeOf<PostgresAuthenticationRateLimiter>());
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(), Is.TypeOf<PostgresSecurityEventSink>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAccountSecurityGuard>(), Is.TypeOf<TestAccountSecurityGuard>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarOperationsSummaryService>(), Is.TypeOf<AshlarOperationsSummaryService>());
            Assert.That(provider.GetServices<IHostedService>().OfType<PostgresEmailOutboxHostedService>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<IHostedService>().OfType<PostgresAshlarCleanupHostedService>(), Has.Exactly(1).Items);
            Assert.That(provider.GetServices<IHostedService>().OfType<PostgresSecurityEventWebhookOutboxHostedService>(), Has.Exactly(1).Items);
        }
    }

    [Test]
    public void AddAshlarPostgresOperationalLayersWithoutHostedMethodsDoNotRegisterHostedServices()
    {
        using var dataSource = CreateDataSource("operational");
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddScoped<IAccountSecurityGuard, TestAccountSecurityGuard>();
        services.AddSingleton<ISecretProtector, TestSecretProtector>();
        services.AddAshlarPostgres(dataSource);
        services.AddAshlarPostgresCleanup();
        services.AddAshlarPostgresEmailOutboxDispatcher<TestEmailTransport>();
        services.AddAshlarPostgresSecurityEventWebhookDispatcher();

        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IAshlarCleanupService),
            typeof(IEmailOutboxDispatcher),
            typeof(PostgresSecurityEventWebhookOutboxDispatcher),
            typeof(IAshlarOperationsSummaryService));

        Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
    }

    private static NpgsqlDataSource CreateDataSource(string host)
    {
        return new NpgsqlDataSourceBuilder(CreateConnectionString(host)).Build();
    }

    private static string CreateConnectionString(string host)
    {
        return $"Host={host}.invalid;Database=ashlar;Username=ashlar;Password=ashlar";
    }

    private sealed class TestAccountSecurityGuard : IAccountSecurityGuard
    {
        public Task<Result> CanChangeAccountStateAsync(IUser user, UserAccountState targetState, AccountSecurityGuardContext request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class TestAccountSecurityOperationAuthorizer : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(true);
    }

    private sealed class TestSecretProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => data;

        public byte[] Unprotect(byte[] data) => data;
    }

    private sealed class TestEmailTransport : IEmailTransport
    {
        public Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
