using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Ashlar.Operational;

/// <summary>
/// Runs periodic Ashlar cleanup for hosted service adapters.
/// </summary>
public sealed class AshlarCleanupHostedServiceRunner
{
    private static readonly Action<ILogger, int, int, int, int, int, int, Exception?> CleanupRunCompleted =
        LoggerMessage.Define<int, int, int, int, int, int>(
            LogLevel.Debug,
            new EventId(1000, nameof(CleanupRunCompleted)),
            "Completed Ashlar cleanup run. ExpiredCredentials={ExpiredCredentials} ExpiredSessions={ExpiredSessions} ExpiredInvitations={ExpiredInvitations} ExpiredHandshakes={ExpiredHandshakes} ExpiredRateLimits={ExpiredRateLimits} TotalItemsProcessed={TotalItemsProcessed}");

    private static readonly Action<ILogger, Exception?> CleanupRunFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1001, nameof(CleanupRunFailed)),
            "Ashlar cleanup hosted service run failed.");

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeProvider _timeProvider;
    private readonly AshlarCleanupOptions _options;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AshlarCleanupHostedServiceRunner" /> class.
    /// </summary>
    /// <param name="scopeFactory">The scope factory used to resolve cleanup services.</param>
    /// <param name="timeProvider">The time provider used by the periodic timer.</param>
    /// <param name="options">The cleanup options.</param>
    /// <param name="logger">The logger used for cleanup run outcomes.</param>
    public AshlarCleanupHostedServiceRunner(
        IServiceScopeFactory scopeFactory,
        TimeProvider timeProvider,
        IOptions<AshlarCleanupOptions> options,
        ILogger logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Runs cleanup immediately and then on each configured interval until canceled.
    /// </summary>
    /// <param name="stoppingToken">The token that cancels the hosted cleanup loop.</param>
    /// <returns>A task that completes when the cleanup loop stops.</returns>
    public async Task ExecuteAsync(CancellationToken stoppingToken)
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
