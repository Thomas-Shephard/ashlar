using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres;

/// <summary>
/// A background service that periodically triggers the <see cref="IEmailOutboxDispatcher"/>.
/// </summary>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="options">The options value.</param>
public sealed class PostgresEmailOutboxHostedService(
    IServiceProvider serviceProvider,
    IOptions<PostgresEmailOutboxOptions> options) : BackgroundService
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly PostgresEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;

    /// <summary>
    /// Validates options and starts the background email outbox dispatcher.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous start operation.</returns>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (!PostgresEmailOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Email outbox options are invalid.");
        }

        return base.StartAsync(cancellationToken);
    }

    /// <summary>
    /// Performs the execute <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="stoppingToken">The stopping token value.</param>
    /// <returns>The operation result.</returns>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                int processedCount;
                using (var scope = _serviceProvider.CreateScope())
                {
                    var dispatcher = scope.ServiceProvider.GetRequiredService<IEmailOutboxDispatcher>();
                    processedCount = await dispatcher.ProcessBatchAsync(stoppingToken);
                }

                if (processedCount < _options.BatchSize)
                {
                    await Task.Delay(_options.PollingInterval, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                // TODO: log here.
                if (!await DelayUntilNextPollAsync(_options.PollingInterval, stoppingToken))
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
