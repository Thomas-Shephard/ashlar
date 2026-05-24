using Ashlar.Operational;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Operational;

/// <summary>
/// Provides postgres ashlar cleanup hosted service behavior.
/// </summary>
/// <param name="scopeFactory">The scope factory value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class PostgresAshlarCleanupHostedService(
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    IOptions<AshlarCleanupOptions> options,
    ILogger<PostgresAshlarCleanupHostedService>? logger = null) : BackgroundService
{
    private readonly AshlarCleanupHostedServiceRunner _runner = new(
        scopeFactory,
        timeProvider,
        options,
        logger ?? NullLogger<PostgresAshlarCleanupHostedService>.Instance);

    /// <summary>
    /// Performs the execute <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="stoppingToken">The stopping token value.</param>
    /// <returns>The operation result.</returns>
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _runner.ExecuteAsync(stoppingToken);
}
