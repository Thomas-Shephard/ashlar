using Ashlar.Identity.Models.Totp;

namespace Ashlar.Sample.AspNetCore.Extensions;

internal static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSampleServices(
        this IServiceCollection services,
        IConfiguration configuration,
        DevelopmentPostgresStartupResult postgresStartup)
    {
        services.AddOptions<SampleAshlarOptions>()
            .Bind(configuration.GetSection("Ashlar"))
            .Validate(options => Uri.TryCreate(options.PublicAppUrl, UriKind.Absolute, out _), "PublicAppUrl must be an absolute URL.")
            .ValidateOnStart();

        var sampleOptions = configuration.GetSection("Ashlar").Get<SampleAshlarOptions>()
            ?? throw new InvalidOperationException("Missing Ashlar configuration.");

        services.AddDataProtection();

        services.AddAshlarIdentity();
        services.AddAshlarPostgres(postgresStartup.ConnectionString);
        services.AddAshlarDataProtectionSecretProtector();
        services.AddAshlarMagicLinkSignIn(options => options.LinkTokenParameterName = "t");
        services.AddAshlarInvitations();
        services.AddAshlarBootstrap(options =>
        {
            options.Grants.Add(new Identity.Models.BootstrapGrantTemplate { Role = "admin" });
        });
        services.AddAshlarAuthorization();
        services.AddAshlarMfaOrchestration();
        services.AddAshlarRequireMfaWhenCredentialExists(options =>
        {
            options.CredentialProviderKeys.Add(TotpOptions.DefaultProviderKey);
            options.RequiredFactors.Add("totp");
        });
        services.AddAshlarTotp();
        services.AddAshlarRecoveryCodes();
        services.AddAshlarPostgresAuditSink();
        services.AddAshlarPostgresRateLimiting();
        services.AddAshlarPostgresEmailOutboxHostedService<DevelopmentEmailTransport>(options =>
        {
            options.BatchSize = sampleOptions.Outbox.BatchSize;
            options.PollingInterval = sampleOptions.Outbox.PollingInterval;
        });
        services.AddAshlarPostgresCleanupHostedService(options =>
        {
            options.CleanupInterval = sampleOptions.Cleanup.CleanupInterval;
        });

        services.AddAshlarAspNetCoreSessions(options =>
        {
            options.CookieName = sampleOptions.Cookie.Name;
            options.Cookie.SecurePolicy = sampleOptions.Cookie.Secure
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;
        });

        services.AddAshlarAspNetCoreAuthorization(options =>
        {
            options.AddRolePolicy("admin", "admin");
            options.AddPermissionPolicy("project.manage", "project.manage", scope =>
            {
                scope.ScopeType = "project";
                scope.ScopeIdRouteValueName = "projectId";
            });
        });

        services.AddScoped<DevelopmentEmailTransport>();

        if (postgresStartup.Container != null)
        {
            services.AddSingleton(postgresStartup.Container);
        }

        return services;
    }
}
