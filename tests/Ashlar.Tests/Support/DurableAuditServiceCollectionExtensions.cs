using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Tests.Support;

internal static class DurableAuditServiceCollectionExtensions
{
    public static IServiceCollection AddDurableAuditForTests(this IServiceCollection services)
    {
        services.AddScoped<IAshlarTransactionProvider, RecordingTransactionProvider>();
        services.AddScoped<IPersistentSecurityEventSink, TestPersistentSecurityEventSink>();
        return services;
    }

    private sealed class TestPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
