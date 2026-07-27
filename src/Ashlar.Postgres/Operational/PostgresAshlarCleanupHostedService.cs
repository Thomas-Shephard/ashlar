using Ashlar.Operational;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Operational;

internal sealed class PostgresAshlarCleanupHostedService : BackgroundService
{
    private readonly AshlarCleanupHostedServiceRunner _runner;

    public PostgresAshlarCleanupHostedService(
        IServiceScopeFactory scopeFactory,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<PostgresAshlarCleanupHostedService>? logger = null)
        : this(
            scopeFactory,
            timeProvider,
            options,
            logger,
            static (services, cancellationToken) =>
                services.GetRequiredService<PostgresAshlarCleanupService>().CleanupAsync(cancellationToken))
    {
    }

    internal PostgresAshlarCleanupHostedService(
        IServiceScopeFactory scopeFactory,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<PostgresAshlarCleanupHostedService>? logger,
        Func<IServiceProvider, CancellationToken, Task<AshlarCleanupResult>> cleanup)
    {
        _runner = new(
            scopeFactory,
            timeProvider,
            options,
            logger ?? NullLogger<PostgresAshlarCleanupHostedService>.Instance,
            cleanup);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _runner.ExecuteAsync(stoppingToken);
}
