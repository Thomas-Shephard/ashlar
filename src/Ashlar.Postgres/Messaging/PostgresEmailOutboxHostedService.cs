using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Postgres.Messaging;

/// <summary>
/// A background service that periodically dispatches the PostgreSQL email outbox.
/// </summary>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class PostgresEmailOutboxHostedService(
    IServiceProvider serviceProvider,
    IOptions<PostgresEmailOutboxOptions> options,
    ILogger<PostgresEmailOutboxHostedService>? logger = null) : BackgroundService
{
    private static readonly Action<ILogger, int, Exception?> OutboxBatchFailed =
        LoggerMessage.Define<int>(
            LogLevel.Error,
            new EventId(1000, nameof(OutboxBatchFailed)),
            "PostgreSQL email outbox hosted service batch failed. BatchSize={BatchSize}");

    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly PostgresEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<PostgresEmailOutboxHostedService> _logger = logger ?? NullLogger<PostgresEmailOutboxHostedService>.Instance;

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
        await OutboxLoopRunner.RunHostedLoopAsync(
            _serviceProvider,
            _options.BatchSize,
            _options.PollingInterval,
            _logger,
            static (provider, token) => provider.GetRequiredService<IEmailOutboxDispatcher>().ProcessBatchAsync(token),
            OutboxBatchFailed,
            stoppingToken);
    }
}
