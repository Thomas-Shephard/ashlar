using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace Ashlar.Messaging;

/// <summary>
/// Represents a persisted email outbox entry that is ready for dispatch.
/// </summary>
public sealed class EmailOutboxEntry
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Gets or sets the to address value.
    /// </summary>
    public required string ToAddress { get; init; }

    /// <summary>
    /// Gets or sets the from address value.
    /// </summary>
    public string? FromAddress { get; init; }

    /// <summary>
    /// Gets or sets the reply to address value.
    /// </summary>
    public string? ReplyToAddress { get; init; }

    /// <summary>
    /// Gets or sets the subject value.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Gets or sets the text body value.
    /// </summary>
    public string? TextBody { get; init; }

    /// <summary>
    /// Gets or sets the html body value.
    /// </summary>
    public string? HtmlBody { get; init; }

    /// <summary>
    /// Gets or sets the serialized headers value.
    /// </summary>
    public string? Headers { get; init; }

    /// <summary>
    /// Gets or sets the serialized metadata value.
    /// </summary>
    public string? Metadata { get; init; }

    /// <summary>
    /// Gets or sets the attempt count value.
    /// </summary>
    public int AttemptCount { get; init; }
}

/// <summary>
/// Represents a computed outbox delivery failure update.
/// </summary>
/// <param name="AttemptCount">The new attempt count.</param>
/// <param name="FailedAt">The final failure timestamp, if attempts are exhausted.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastError">The truncated error text.</param>
public sealed record EmailOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);

/// <summary>
/// Shared email outbox dispatch behavior for persistence providers.
/// </summary>
public static class EmailOutboxDispatch
{
    private const int MaxLastErrorLength = 1000;

    /// <summary>
    /// Runs a hosted email outbox polling loop.
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
                using (var scope = serviceProvider.CreateScope())
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

    /// <summary>
    /// Computes the provider-specific values used to mark a failed delivery attempt.
    /// </summary>
    /// <param name="attemptCount">The current attempt count.</param>
    /// <param name="maxAttempts">The configured max attempts.</param>
    /// <param name="initialRetryDelay">The initial retry delay.</param>
    /// <param name="now">The current UTC time.</param>
    /// <param name="exception">The delivery exception.</param>
    /// <returns>The computed failure update.</returns>
    public static EmailOutboxFailureUpdate CreateFailureUpdate(
        int attemptCount,
        int maxAttempts,
        TimeSpan initialRetryDelay,
        DateTimeOffset now,
        Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        var nextAttemptCount = attemptCount + 1;
        var isFinalFailure = nextAttemptCount >= maxAttempts;
        var backoffMultiplier = Math.Pow(2, nextAttemptCount - 1);
        var maxDelayTicks = TimeSpan.FromDays(7).Ticks;
        var delayTicks = Math.Min(initialRetryDelay.Ticks * backoffMultiplier, maxDelayTicks);
        var availableAt = isFinalFailure ? now : now.AddTicks((long)delayTicks);
        var lastError = exception.ToString();
        if (lastError.Length > MaxLastErrorLength)
        {
            lastError = lastError[..MaxLastErrorLength];
        }

        return new EmailOutboxFailureUpdate(
            nextAttemptCount,
            isFinalFailure ? now : null,
            availableAt,
            lastError);
    }

    /// <summary>
    /// Maps a persisted outbox entry to an email message.
    /// </summary>
    /// <param name="entry">The outbox entry.</param>
    /// <returns>The email message.</returns>
    public static EmailMessage MapToEmailMessage(EmailOutboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var headers = entry.Headers != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers) : null;
        var metadata = entry.Metadata != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Metadata) : null;

        return new EmailMessage(
            entry.ToAddress,
            entry.Subject,
            entry.TextBody,
            entry.HtmlBody,
            new EmailMessageOptions
            {
                From = entry.FromAddress,
                ReplyTo = entry.ReplyToAddress,
                Headers = headers,
                Metadata = metadata
            });
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


