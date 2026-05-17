using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.AspNetCore.Authorization;

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
            .Validate(options => Uri.TryCreate(options.PublicAppUrl, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp) &&
                uri.AbsolutePath == "/" &&
                string.IsNullOrEmpty(uri.UserInfo) &&
                string.IsNullOrEmpty(uri.Query) &&
                string.IsNullOrEmpty(uri.Fragment), "PublicAppUrl must be a root http or https origin (no path, user info, query string, or fragment).")
            .ValidateOnStart();

        var sampleOptions = configuration.GetSection("Ashlar").Get<SampleAshlarOptions>()
            ?? throw new InvalidOperationException("Missing Ashlar configuration.");

        services.AddDataProtection();

        services.AddAshlarIdentity();
        services.Configure<Identity.Models.UriValidationOptions>(options =>
        {
            var publicAppUri = new Uri(sampleOptions.PublicAppUrl);
            options.AllowedCallbackUris.Add(new Uri(publicAppUri, "/auth/magic-link").AbsoluteUri);
            options.AllowedCallbackUris.Add(new Uri(publicAppUri, "/invitations/accept").AbsoluteUri);
            options.AllowedCallbackUris.Add(new Uri(publicAppUri, "/account/verify-email").AbsoluteUri);
            options.AllowedCallbackUris.Add(new Uri(publicAppUri, "/account/change-email").AbsoluteUri);
        });
        services.AddAshlarPostgres(postgresStartup.ConnectionString);
        services.AddAshlarDataProtectionSecretProtector();
        services.AddAshlarMagicLinkSignIn(options => options.LinkTokenParameterName = "t");
        services.AddAshlarEmailCodeSignIn();
        services.AddAshlarEmailVerification();
        services.AddAshlarEmailChange();
        services.AddAshlarSecurityNotifications();
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
            options.RequiredFactors.Add(AuthenticationFactorTypes.Totp);
        });
        services.AddAshlarTotp();
        services.AddAshlarRecoveryCodes();
        services.AddAshlarPasskeys(options =>
        {
            var publicAppUri = new Uri(sampleOptions.PublicAppUrl);
            options.RelyingPartyId = publicAppUri.Host;
            options.RelyingPartyName = "Ashlar Sample";
            options.Origin = publicAppUri.GetLeftPart(UriPartial.Authority);
        });
        services.AddAshlarPostgresAuditSink();
        services.AddScoped<IAccountSecurityGuard, SampleAccountSecurityGuard>();
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
            options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(10);
            options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
            options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.RecoveryCode);
            options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
            options.RequireFreshMfa();
            options.RequireFreshMfaIfAvailable();
            options.AddRolePolicy("admin", "admin");
            options.AddPermissionPolicy("project.manage", "project.manage", scope =>
            {
                scope.ScopeType = "project";
                scope.ScopeIdRouteValueName = "projectId";
            });
        });
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, SampleStepUpAuthorizationResultHandler>();

        services.AddScoped<DevelopmentEmailTransport>();

        if (postgresStartup.Container != null)
        {
            services.AddSingleton(postgresStartup.Container);
        }

        return services;
    }
}
