using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Ashlar.Messaging;

/// <summary>
/// Shared hosted outbox polling behavior for persistence providers.
/// </summary>
public static class OutboxLoopRunner
{
    /// <summary>
    /// Runs a hosted outbox polling loop.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    /// <param name="batchSize">The configured batch size.</param>
    /// <param name="pollingInterval">The polling interval.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="processBatchAsync">The provider-specific scoped batch processor.</param>
    /// <param name="logBatchFailed">The provider-specific failure logger.</param>
    /// <param name="stoppingToken">The stopping token.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public static async Task RunHostedLoopAsync(
        IServiceProvider serviceProvider,
        int batchSize,
        TimeSpan pollingInterval,
        ILogger logger,
        Func<IServiceProvider, CancellationToken, Task<int>> processBatchAsync,
        Action<ILogger, int, Exception?> logBatchFailed,
        CancellationToken stoppingToken)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(processBatchAsync);
        ArgumentNullException.ThrowIfNull(logBatchFailed);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                int processedCount;
                await using (var scope = serviceProvider.CreateAsyncScope())
                {
                    processedCount = await processBatchAsync(scope.ServiceProvider, stoppingToken);
                }

                if (processedCount < batchSize)
                {
                    await Task.Delay(pollingInterval, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logBatchFailed(logger, batchSize, exception);
                if (!await DelayUntilNextPollAsync(pollingInterval, stoppingToken))
                {
                    break;
                }
            }
        }
    }

    private static async ValueTask<bool> DelayUntilNextPollAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(delay, stoppingToken);
            return true;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return false;
        }
    }
}
