using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Ashlar.Tests.Support;

internal static class DurableAuditServiceCollectionExtensions
{
    public static IServiceCollection AddDurableAuditForTests(this IServiceCollection services)
    {
        services.ReplaceAshlarProviderScoped<IPersistentSecurityEventSink>(_ => new TestPersistentSecurityEventSink());
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>("Test");
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        if (HasProviderService<IUserRepository>(services))
            services.AddAshlarDurableTransactionParticipant<IUserRepository>();
        if (HasProviderService<ICredentialRepository>(services))
            services.AddAshlarDurableTransactionParticipant<ICredentialRepository>();
        if (HasProviderService<IAuthenticationSessionRepository>(services))
            services.AddAshlarDurableTransactionParticipant<IAuthenticationSessionRepository>();
        if (HasProviderService<IRememberedMfaDeviceRepository>(services))
            services.AddAshlarDurableTransactionParticipant<IRememberedMfaDeviceRepository>();
        if (HasProviderService<IAccountLockoutRepository>(services))
            services.AddAshlarDurableTransactionParticipant<IAccountLockoutRepository>();
        services.Replace(ServiceDescriptor.Scoped<SecurityEventFanOutSink>(provider => new SecurityEventFanOutSink(
            Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(provider),
            handlers: provider.GetServices<ISecurityEventHandler>(),
            transactionProvider: provider.GetRequiredService<AshlarDurableTransactionProvider>())));
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
        return services;
    }

    private static bool HasProviderService<TService>(IServiceCollection services) where TService : class =>
        services.Any(descriptor => descriptor.ServiceType == typeof(AshlarProviderService<TService>));

    private sealed class TestPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
