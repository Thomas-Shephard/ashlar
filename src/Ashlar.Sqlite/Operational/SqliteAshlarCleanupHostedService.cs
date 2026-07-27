using Ashlar.Operational;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Operational;

internal sealed class SqliteAshlarCleanupHostedService : BackgroundService
{
    private readonly AshlarCleanupHostedServiceRunner _runner;

    public SqliteAshlarCleanupHostedService(
        IServiceScopeFactory scopeFactory,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<SqliteAshlarCleanupHostedService>? logger = null)
        : this(
            scopeFactory,
            timeProvider,
            options,
            logger,
            static (services, cancellationToken) =>
                services.GetRequiredService<SqliteAshlarCleanupService>().CleanupAsync(cancellationToken))
    {
    }

    internal SqliteAshlarCleanupHostedService(
        IServiceScopeFactory scopeFactory,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger<SqliteAshlarCleanupHostedService>? logger,
        Func<IServiceProvider, CancellationToken, Task<AshlarCleanupResult>> cleanup)
    {
        _runner = new(
            scopeFactory,
            timeProvider,
            options,
            logger ?? NullLogger<SqliteAshlarCleanupHostedService>.Instance,
            cleanup);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _runner.ExecuteAsync(stoppingToken);
}
