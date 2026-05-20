using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Sqlite.Messaging;

/// <summary>
/// A background service that periodically triggers the SQLite email outbox dispatcher.
/// </summary>
/// <typeparam name="TTransport">The transport type.</typeparam>
/// <param name="serviceProvider">The service provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="logger">The logger value.</param>
public sealed class SqliteEmailOutboxHostedService<TTransport>(
    IServiceProvider serviceProvider,
    IOptions<SqliteEmailOutboxOptions> options,
    ILogger<SqliteEmailOutboxHostedService<TTransport>>? logger = null) : BackgroundService
    where TTransport : IEmailTransport
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly SqliteEmailOutboxOptions _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
    private readonly ILogger<SqliteEmailOutboxHostedService<TTransport>> _logger = logger ?? NullLogger<SqliteEmailOutboxHostedService<TTransport>>.Instance;

    /// <summary>
    /// Validates options and starts the background email outbox dispatcher.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous start operation.</returns>
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (!SqliteEmailOutboxOptions.Validate(_options))
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
        await EmailOutboxDispatch.RunHostedLoopAsync(
            _serviceProvider,
            _options.BatchSize,
            _options.PollingInterval,
            _logger,
            static (provider, token) => provider.GetRequiredService<SqliteEmailOutboxDispatcher<TTransport>>().ProcessBatchAsync(token),
            SqliteEmailOutboxHostedServiceLog.OutboxBatchFailed,
            stoppingToken);
    }
}

internal static class SqliteEmailOutboxHostedServiceLog
{
    public static readonly Action<ILogger, int, Exception?> OutboxBatchFailed =
        LoggerMessage.Define<int>(
            LogLevel.Error,
            new EventId(1000, nameof(OutboxBatchFailed)),
            "SQLite email outbox hosted service batch failed. BatchSize={BatchSize}");
}






