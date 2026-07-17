using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Ashlar.Tests.Support;

internal static class DurableAuditServiceCollectionExtensions
{
    public static IServiceCollection AddDurableAuditForTests(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Scoped<IPersistentSecurityEventSink, TestPersistentSecurityEventSink>());
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>();
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IUserRepository)))
            services.AddAshlarDurableTransactionParticipant<IUserRepository>();
        if (services.Any(descriptor => descriptor.ServiceType == typeof(ICredentialRepository)))
            services.AddAshlarDurableTransactionParticipant<ICredentialRepository>();
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IAuthenticationSessionRepository)))
            services.AddAshlarDurableTransactionParticipant<IAuthenticationSessionRepository>();
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IRememberedMfaDeviceRepository)))
            services.AddAshlarDurableTransactionParticipant<IRememberedMfaDeviceRepository>();
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IAccountLockoutRepository)))
            services.AddAshlarDurableTransactionParticipant<IAccountLockoutRepository>();
        services.Replace(ServiceDescriptor.Scoped<SecurityEventFanOutSink>(provider => new SecurityEventFanOutSink(
            provider.GetRequiredService<IPersistentSecurityEventSink>(),
            handlers: provider.GetServices<ISecurityEventHandler>(),
            transactionProvider: provider.GetRequiredService<AshlarDurableTransactionProvider>())));
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
        return services;
    }

    private sealed class TestPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
