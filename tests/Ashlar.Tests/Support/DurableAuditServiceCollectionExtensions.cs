using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Ashlar.Tests.Support;

internal static class DurableAuditServiceCollectionExtensions
{
    public static IServiceCollection AddDurableAuditForTests(this IServiceCollection services)
    {
        services.TryAddScoped<RecordingTransactionProvider>();
        services.Replace(ServiceDescriptor.Scoped<IAshlarTransactionProvider>(provider => provider.GetRequiredService<RecordingTransactionProvider>()));
        services.Replace(ServiceDescriptor.Scoped<IAshlarDurableTransactionProvider>(provider => provider.GetRequiredService<RecordingTransactionProvider>()));
        services.Replace(ServiceDescriptor.Scoped<IPersistentSecurityEventSink, TestPersistentSecurityEventSink>());
        services.Replace(ServiceDescriptor.Scoped<SecurityEventFanOutSink>(provider => new SecurityEventFanOutSink(
            provider.GetRequiredService<IPersistentSecurityEventSink>(),
            handlers: provider.GetServices<ISecurityEventHandler>(),
            transactionProvider: provider.GetRequiredService<IAshlarDurableTransactionProvider>())));
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
        return services;
    }

    private sealed class TestPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
