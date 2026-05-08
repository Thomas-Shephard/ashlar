using Ashlar.Operational;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres;

public sealed class PostgresAshlarCleanupHostedService(
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    IOptions<AshlarCleanupOptions> options) : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly AshlarCleanupOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!AshlarCleanupOptions.Validate(_options))
        {
            throw new InvalidOperationException("Cleanup options are invalid.");
        }

        using var timer = new PeriodicTimer(_options.CleanupInterval, _timeProvider);
        await RunCleanupAsync(stoppingToken);
        while (await WaitForNextTickAsync(timer, stoppingToken))
        {
            await RunCleanupAsync(stoppingToken);
        }
    }

    private async Task RunCleanupAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var cleanupService = scope.ServiceProvider.GetRequiredService<IAshlarCleanupService>();
            await cleanupService.CleanupAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Expected during host shutdown.
        }
        catch (Exception exception)
        {
            _ = exception;
            // TODO: Log hosted cleanup failures when Ashlar has an operational logging policy.
        }
    }

    private static async ValueTask<bool> WaitForNextTickAsync(PeriodicTimer timer, CancellationToken stoppingToken)
    {
        try
        {
            return await timer.WaitForNextTickAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
