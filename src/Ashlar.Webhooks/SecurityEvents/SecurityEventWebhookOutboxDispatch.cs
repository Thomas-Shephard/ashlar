using System.Net.Http.Headers;
using System.Text.Json;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Represents a prepared durable security event webhook outbox entry ready for dispatch.
/// </summary>
public sealed class AshlarSecurityEventWebhookOutboxEntry
{
    /// <summary>
    /// Gets the durable outbox entry identifier.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Gets the destination URI.
    /// </summary>
    public required string Uri { get; init; }

    /// <summary>
    /// Gets the final prepared request body.
    /// </summary>
    public required byte[] Body { get; init; }

    /// <summary>
    /// Gets the serialized final prepared request headers.
    /// </summary>
    public required string Headers { get; init; }

    /// <summary>
    /// Gets the request timeout in milliseconds.
    /// </summary>
    public long TimeoutMs { get; init; }

    /// <summary>
    /// Gets the number of previous delivery attempts.
    /// </summary>
    public int AttemptCount { get; init; }
}

/// <summary>
/// Provides shared helpers for dispatching durable security event webhook outbox entries.
/// </summary>
public static class AshlarSecurityEventWebhookOutboxDispatch
{
    private const int MaxLastErrorLength = 1000;

    /// <summary>
    /// Maps a durable outbox entry to the HTTP request that should be sent.
    /// </summary>
    /// <param name="entry">The durable outbox entry.</param>
    /// <returns>The HTTP request message.</returns>
    public static HttpRequestMessage MapToHttpRequest(AshlarSecurityEventWebhookOutboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var request = new HttpRequestMessage(HttpMethod.Post, entry.Uri);
        request.Content = new ReadOnlyMemoryContent(entry.Body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers);
        if (headers != null)
        {
            headers
                .Where(header => ShouldAddAsContentHeader(request, header))
                .ToList()
                .ForEach(header => request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value));
        }

        return request;
    }

    /// <summary>
    /// Sends a durable outbox entry and applies the provided success or failure persistence callbacks.
    /// </summary>
    /// <param name="entry">The durable outbox entry.</param>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="httpClientName">The named HTTP client to use.</param>
    /// <param name="maxAttempts">The maximum configured delivery attempts.</param>
    /// <param name="markAsSentAsync">The callback that persists successful delivery state.</param>
    /// <param name="markAsFailedAsync">The callback that persists failed delivery state.</param>
    /// <param name="logDeliveryFailed">The callback that logs failed delivery attempts.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task that represents the asynchronous dispatch operation.</returns>
    public static async Task DispatchAsync(
        AshlarSecurityEventWebhookOutboxEntry entry,
        IHttpClientFactory httpClientFactory,
        string httpClientName,
        int maxAttempts,
        Func<Guid, CancellationToken, Task> markAsSentAsync,
        Func<AshlarSecurityEventWebhookOutboxEntry, Exception, CancellationToken, Task> markAsFailedAsync,
        Action<Guid, int, bool, Exception> logDeliveryFailed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpClientName);
        ArgumentNullException.ThrowIfNull(markAsSentAsync);
        ArgumentNullException.ThrowIfNull(markAsFailedAsync);
        ArgumentNullException.ThrowIfNull(logDeliveryFailed);

        try
        {
            using var request = MapToHttpRequest(entry);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(entry.TimeoutMs));
            var client = httpClientFactory.CreateClient(httpClientName);
            using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Webhook endpoint returned HTTP {(int)response.StatusCode}.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var attemptCount = entry.AttemptCount + 1;
            logDeliveryFailed(entry.Id, attemptCount, attemptCount >= maxAttempts, exception);
            await markAsFailedAsync(entry, exception, CancellationToken.None).ConfigureAwait(false);
            return;
        }

        await markAsSentAsync(entry.Id, CancellationToken.None).ConfigureAwait(false);
    }

    private static bool ShouldAddAsContentHeader(HttpRequestMessage request, KeyValuePair<string, string> header)
    {
        return !request.Headers.TryAddWithoutValidation(header.Key, header.Value);
    }

    /// <summary>
    /// Creates the retry or terminal-failure state for a failed dispatch attempt.
    /// </summary>
    /// <param name="attemptCount">The number of previous delivery attempts.</param>
    /// <param name="maxAttempts">The maximum number of delivery attempts.</param>
    /// <param name="initialRetryDelay">The initial retry delay.</param>
    /// <param name="now">The current timestamp.</param>
    /// <param name="exception">The dispatch exception.</param>
    /// <returns>The failure update to persist.</returns>
    public static AshlarSecurityEventWebhookOutboxFailureUpdate CreateFailureUpdate(
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
        var lastError = exception.ToString();
        if (lastError.Length > MaxLastErrorLength)
        {
            lastError = lastError[..MaxLastErrorLength];
        }

        return new AshlarSecurityEventWebhookOutboxFailureUpdate(
            nextAttemptCount,
            isFinalFailure ? now : null,
            isFinalFailure ? now : now.AddTicks((long)delayTicks),
            lastError);
    }
}

/// <summary>
/// Represents durable state changes for a failed security event webhook dispatch attempt.
/// </summary>
/// <param name="AttemptCount">The updated attempt count.</param>
/// <param name="FailedAt">The terminal failure timestamp, if the entry exhausted retry attempts.</param>
/// <param name="AvailableAt">The next time the entry is eligible for dispatch.</param>
/// <param name="LastError">The safe truncated error text to persist.</param>
public sealed record AshlarSecurityEventWebhookOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);
