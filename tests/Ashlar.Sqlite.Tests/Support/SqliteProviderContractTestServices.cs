namespace Ashlar.Sqlite.Tests.Support;

using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;

internal static class SqliteProviderContractTestServices
{
    internal static IServiceCollection AddSqliteProviderContractTestServices(this IServiceCollection services)
    {
        services.AddScoped<IUserRepository, SqliteUserRepository>();
        services.AddScoped<ICredentialRepository, SqliteCredentialRepository>();
        services.AddScoped<IAccountLockoutRepository, SqliteAccountLockoutRepository>();
        services.AddScoped<IBootstrapStateRepository, SqliteBootstrapStateRepository>();
        services.AddScoped<IInvitationRepository, SqliteInvitationRepository>();
        services.AddScoped<IAuthenticationSessionRepository, SqliteAuthenticationSessionRepository>();
        services.AddScoped<IRememberedMfaDeviceRepository, SqliteRememberedMfaDeviceRepository>();
        services.AddScoped<IAuthenticationHandshakeRepository, SqliteAuthenticationHandshakeRepository>();
        services.AddScoped<IAuthorizationGrantRepository, SqliteAuthorizationGrantRepository>();
        services.AddScoped<IPersistentSecurityEventSink, SqliteSecurityEventSink>();
        services.AddScoped<IPasskeyChallengeRepository, SqlitePasskeyChallengeRepository>();
        services.AddScoped<IAuthenticationRateLimitAdministrationRepository, SqliteAuthenticationRateLimitAdministrationRepository>();
        return services;
    }

    internal static IServiceCollection AddSqliteWebhookProviderContractTestService(this IServiceCollection services)
    {
        services.AddScoped<IAshlarSecurityEventWebhookEnqueuer, SqliteSecurityEventWebhookEnqueuer>();
        return services;
    }

    internal static void AssertSqliteProviderContractsRegistered(this IServiceProvider provider)
    {
        Assert.That(new[]
        {
            provider.IsAshlarProviderServiceRegistered<IUserRepository>(),
            provider.IsAshlarProviderServiceRegistered<ICredentialRepository>(),
            provider.IsAshlarProviderServiceRegistered<IAccountLockoutRepository>(),
            provider.IsAshlarProviderServiceRegistered<IBootstrapStateRepository>(),
            provider.IsAshlarProviderServiceRegistered<IInvitationRepository>(),
            provider.IsAshlarProviderServiceRegistered<IAuthenticationSessionRepository>(),
            provider.IsAshlarProviderServiceRegistered<IRememberedMfaDeviceRepository>(),
            provider.IsAshlarProviderServiceRegistered<IAuthenticationHandshakeRepository>(),
            provider.IsAshlarProviderServiceRegistered<IAuthorizationGrantRepository>(),
            provider.IsAshlarProviderServiceRegistered<IPersistentSecurityEventSink>(),
            provider.IsAshlarProviderServiceRegistered<IPasskeyChallengeRepository>(),
            provider.IsAshlarProviderServiceRegistered<IAuthenticationRateLimitAdministrationRepository>(),
            provider.IsAshlarProviderServiceRegistered<SqliteSecurityEventWebhookEnqueuer>()
        }, Is.All.True);
    }
}
