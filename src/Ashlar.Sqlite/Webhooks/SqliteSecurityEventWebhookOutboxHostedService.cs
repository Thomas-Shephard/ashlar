using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Webhooks;

/// <summary>
/// Background service that periodically dispatches SQLite-backed security event webhook deliveries.
/// </summary>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class SqliteSecurityEventWebhookOutboxHostedService(
    IServiceProvider serviceProvider,
    IOptions<SqliteSecurityEventWebhookOutboxOptions> options,
    ILogger<SqliteSecurityEventWebhookOutboxHostedService>? logger = null) : BackgroundService
{
    private static readonly Action<ILogger, int, Exception?> OutboxBatchFailed =
        LoggerMessage.Define<int>(
            LogLevel.Error,
            new EventId(2000, nameof(OutboxBatchFailed)),
            "SQLite security event webhook outbox hosted service batch failed. BatchSize={BatchSize}");

    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly SqliteSecurityEventWebhookOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<SqliteSecurityEventWebhookOutboxHostedService> _logger = logger ?? NullLogger<SqliteSecurityEventWebhookOutboxHostedService>.Instance;

    /// <summary>
    /// Validates options and starts the background webhook outbox dispatcher.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task that represents the asynchronous start operation.</returns>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (!SqliteSecurityEventWebhookOutboxOptions.Validate(_options))
        {
            throw new InvalidOperationException("Security event webhook outbox options are invalid.");
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
        await OutboxLoopRunner.RunHostedLoopAsync(
            _serviceProvider,
            _options.BatchSize,
            _options.PollingInterval,
            _logger,
            static (provider, token) => provider.GetRequiredService<SqliteSecurityEventWebhookOutboxDispatcher>().ProcessBatchAsync(token),
            OutboxBatchFailed,
            stoppingToken);
    }
}
