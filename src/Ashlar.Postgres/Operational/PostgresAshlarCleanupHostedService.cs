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
    private static readonly Action<ILogger, int, int, int, int, int, int, Exception?> CleanupRunCompleted =
        LoggerMessage.Define<int, int, int, int, int, int>(
            LogLevel.Debug,
            new EventId(1000, nameof(CleanupRunCompleted)),
            "Completed Ashlar cleanup run. ExpiredCredentials={ExpiredCredentials} ExpiredSessions={ExpiredSessions} ExpiredInvitations={ExpiredInvitations} ExpiredHandshakes={ExpiredHandshakes} ExpiredRateLimits={ExpiredRateLimits} TotalDeleted={TotalDeleted}");

    private static readonly Action<ILogger, Exception?> CleanupRunFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1001, nameof(CleanupRunFailed)),
            "Ashlar cleanup hosted service run failed.");

    private readonly IServiceScopeFactory _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
    private readonly TimeProvider _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    private readonly AshlarCleanupOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<PostgresAshlarCleanupHostedService> _logger = logger ?? NullLogger<PostgresAshlarCleanupHostedService>.Instance;

    /// <summary>
    /// Performs the execute <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="stoppingToken">The stopping token value.</param>
    /// <returns>The operation result.</returns>
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
            var result = await cleanupService.CleanupAsync(stoppingToken);
            CleanupRunCompleted(
                _logger,
                result.ExpiredCredentials,
                result.ExpiredSessions,
                result.ExpiredInvitations,
                result.ExpiredHandshakes,
                result.ExpiredRateLimits,
                result.Total,
                null);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Expected during host shutdown.
        }
        catch (Exception exception)
        {
            CleanupRunFailed(_logger, exception);
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






