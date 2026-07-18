namespace Ashlar.Postgres.Tests.Support;

using Ashlar.Authorization.Abstractions;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Webhooks.SecurityEvents;
using Microsoft.Extensions.DependencyInjection;

internal static class PostgresProviderContractTestServices
{
    internal static IServiceCollection AddPostgresProviderContractTestServices(this IServiceCollection services)
    {
        services.AddScoped<IUserRepository, PostgresUserRepository>();
        services.AddScoped<ICredentialRepository, PostgresCredentialRepository>();
        services.AddScoped<IAccountLockoutRepository, PostgresAccountLockoutRepository>();
        services.AddScoped<IBootstrapStateRepository, PostgresBootstrapStateRepository>();
        services.AddScoped<IInvitationRepository, PostgresInvitationRepository>();
        services.AddScoped<IAuthenticationSessionRepository, PostgresAuthenticationSessionRepository>();
        services.AddScoped<IRememberedMfaDeviceRepository, PostgresRememberedMfaDeviceRepository>();
        services.AddScoped<IAuthenticationHandshakeRepository, PostgresAuthenticationHandshakeRepository>();
        services.AddScoped<IAuthorizationGrantRepository, PostgresAuthorizationGrantRepository>();
        services.AddScoped<IPersistentSecurityEventSink, PostgresSecurityEventSink>();
        services.AddScoped<IPasskeyChallengeRepository, PostgresPasskeyChallengeRepository>();
        services.AddScoped<IAuthenticationRateLimitAdministrationRepository, PostgresAuthenticationRateLimitAdministrationRepository>();
        return services;
    }

    internal static IServiceCollection AddPostgresWebhookProviderContractTestService(this IServiceCollection services)
    {
        services.AddScoped<IAshlarSecurityEventWebhookEnqueuer, PostgresSecurityEventWebhookEnqueuer>();
        return services;
    }

    internal static void AssertPostgresProviderContractsRegistered(this IServiceProvider provider)
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
            provider.IsAshlarProviderServiceRegistered<PostgresSecurityEventWebhookEnqueuer>()
        }, Is.All.True);
    }
}
