using System.Diagnostics;
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
/// Provides callbacks and options for dispatching a durable security event webhook outbox entry.
/// </summary>
/// <param name="HttpClientFactory">The HTTP client factory.</param>
/// <param name="HttpClientName">The named HTTP client to use.</param>
/// <param name="MaxAttempts">The maximum configured delivery attempts.</param>
/// <param name="MarkAsSentAsync">The callback that persists successful delivery state.</param>
/// <param name="MarkAsFailedAsync">The callback that persists failed delivery state.</param>
/// <param name="LogDeliveryFailed">The callback that logs failed delivery attempts.</param>
/// <param name="DeliveryObserver">The provider-neutral delivery observer.</param>
public sealed record AshlarSecurityEventWebhookOutboxDispatchContext(
    IHttpClientFactory HttpClientFactory,
    string HttpClientName,
    int MaxAttempts,
    Func<Guid, CancellationToken, Task> MarkAsSentAsync,
    Func<AshlarSecurityEventWebhookOutboxEntry, Exception, CancellationToken, Task> MarkAsFailedAsync,
    Action<Guid, int, bool, Exception> LogDeliveryFailed,
    IAshlarSecurityEventWebhookDeliveryObserver? DeliveryObserver = null);

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

        return MapToHttpRequest(entry, DeserializeHeaders(entry.Headers));
    }

    private static HttpRequestMessage MapToHttpRequest(
        AshlarSecurityEventWebhookOutboxEntry entry,
        Dictionary<string, string>? headers)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, entry.Uri);
        request.Content = new ReadOnlyMemoryContent(entry.Body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        if (headers != null)
        {
            foreach (var header in headers.Where(header => ShouldAddAsContentHeader(request, header)))
            {
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return request;
    }

    /// <summary>
    /// Sends a durable outbox entry and applies the provided success or failure persistence callbacks.
    /// </summary>
    /// <param name="entry">The durable outbox entry.</param>
    /// <param name="context">The dispatch context.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task that represents the asynchronous dispatch operation.</returns>
    public static async Task DispatchAsync(
        AshlarSecurityEventWebhookOutboxEntry entry,
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.HttpClientFactory);
        ArgumentException.ThrowIfNullOrWhiteSpace(context.HttpClientName);
        ArgumentNullException.ThrowIfNull(context.MarkAsSentAsync);
        ArgumentNullException.ThrowIfNull(context.MarkAsFailedAsync);
        ArgumentNullException.ThrowIfNull(context.LogDeliveryFailed);

        var start = Stopwatch.GetTimestamp();
        Dictionary<string, string>? headers = null;
        try
        {
            headers = DeserializeHeaders(entry.Headers);
            using var request = MapToHttpRequest(entry, headers);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(entry.TimeoutMs));
            var client = context.HttpClientFactory.CreateClient(context.HttpClientName);
            using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var exception = new HttpRequestException($"Webhook endpoint returned HTTP {(int)response.StatusCode}.");
                RecordFailure(context, start, AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind, headers);
                await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
                return;
            }

            RecordSuccess(context, start, headers);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            RecordFailure(context, start, AshlarSecurityEventWebhookDeliveryTelemetry.CanceledFailureKind, headers);
            throw;
        }
        catch (OperationCanceledException exception)
        {
            RecordFailure(context, start, AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind, headers);
            await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
            return;
        }
        catch (Exception exception)
        {
            RecordFailure(context, start, AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind, headers);
            await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
            return;
        }

        await context.MarkAsSentAsync(entry.Id, CancellationToken.None).ConfigureAwait(false);
    }

    private static bool ShouldAddAsContentHeader(HttpRequestMessage request, KeyValuePair<string, string> header)
    {
        return !request.Headers.TryAddWithoutValidation(header.Key, header.Value);
    }

    private static async Task MarkAsFailedAsync(
        AshlarSecurityEventWebhookOutboxEntry entry,
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        Exception exception)
    {
        var attemptCount = entry.AttemptCount + 1;
        context.LogDeliveryFailed(entry.Id, attemptCount, attemptCount >= context.MaxAttempts, exception);
        await context.MarkAsFailedAsync(entry, exception, CancellationToken.None).ConfigureAwait(false);
    }

    private static void RecordSuccess(
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        long start,
        Dictionary<string, string>? headers)
    {
        Record(context, start, AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome, null, headers);
    }

    private static void RecordFailure(
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        long start,
        string failureKind,
        Dictionary<string, string>? headers)
    {
        Record(context, start, AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome, failureKind, headers);
    }

    private static void Record(
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        long start,
        string outcome,
        string? failureKind,
        Dictionary<string, string>? headers)
    {
        var observer = context.DeliveryObserver ?? NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance;
        observer.RecordDeliveryAttempt(new AshlarSecurityEventWebhookDeliveryTelemetry(
            AshlarSecurityEventWebhookDeliveryTelemetry.DurableOutboxDeliveryMode,
            GetHeaderValue(headers, "X-Ashlar-Event-Type"),
            GetHeaderValue(headers, "X-Ashlar-Webhook-Endpoint"),
            outcome,
            failureKind,
            Stopwatch.GetElapsedTime(start)));
    }

    private static string? GetHeaderValue(Dictionary<string, string>? headers, string headerName)
    {
        return headers != null && headers.TryGetValue(headerName, out var value) ? value : null;
    }

    private static Dictionary<string, string>? DeserializeHeaders(string headers)
    {
        return JsonSerializer.Deserialize<Dictionary<string, string>>(headers);
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
