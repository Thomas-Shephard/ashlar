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
    /// Gets the endpoint display name used in safe logs and signing.
    /// </summary>
    public required string EndpointName { get; init; }

    /// <summary>
    /// Gets the destination URI.
    /// </summary>
    public required string Uri { get; init; }

    /// <summary>
    /// Gets the security event identifier.
    /// </summary>
    public Guid EventId { get; init; }

    /// <summary>
    /// Gets the security event type.
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// Gets the security event occurrence timestamp.
    /// </summary>
    public DateTimeOffset OccurredAt { get; init; }

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
/// <param name="DestinationValidator">The webhook destination safety validator.</param>
/// <param name="WebhookOptions">The current webhook endpoint configuration.</param>
/// <param name="TimeProvider">The time provider used for dispatch-time signing.</param>
/// <param name="DeliveryObserver">The provider-neutral delivery observer.</param>
public sealed record AshlarSecurityEventWebhookOutboxDispatchContext(
    IHttpClientFactory HttpClientFactory,
    string HttpClientName,
    int MaxAttempts,
    Func<Guid, CancellationToken, Task> MarkAsSentAsync,
    Func<AshlarSecurityEventWebhookOutboxEntry, Exception, CancellationToken, Task> MarkAsFailedAsync,
    Action<Guid, int, bool, Exception> LogDeliveryFailed,
    AshlarSecurityEventWebhookDestinationValidator DestinationValidator,
    AshlarSecurityEventWebhookOptions WebhookOptions,
    TimeProvider TimeProvider,
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
        var content = new ReadOnlyMemoryContent(entry.Body);
        request.Content = content;
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        if (headers != null)
        {
            foreach (var header in headers)
            {
                AddHeader(request, content, header);
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
        ArgumentNullException.ThrowIfNull(context.DestinationValidator);
        ArgumentNullException.ThrowIfNull(context.WebhookOptions);
        ArgumentNullException.ThrowIfNull(context.TimeProvider);

        var start = Stopwatch.GetTimestamp();
        try
        {
            var headers = DeserializeHeaders(entry.Headers);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(entry.TimeoutMs));
            var uri = new Uri(entry.Uri, UriKind.Absolute);
            var destinationValidation = await context.DestinationValidator.ValidateAsync(uri, timeout.Token).ConfigureAwait(false);
            if (!destinationValidation.IsValid)
            {
                var exception = new AshlarSecurityEventWebhookUnsafeDestinationException(destinationValidation.FailureReason);
                RecordFailure(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind);
                await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
                return;
            }

            headers = RegenerateSigningHeaders(entry, context, headers, uri);
            using var request = MapToHttpRequest(entry, headers);
            var client = context.HttpClientFactory.CreateClient(context.HttpClientName);
            using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var exception = new HttpRequestException($"Webhook endpoint returned HTTP {(int)response.StatusCode}.");
                RecordFailure(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind);
                await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
                return;
            }

            RecordSuccess(context, entry, start);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            RecordFailure(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.CanceledFailureKind);
            throw;
        }
        catch (OperationCanceledException exception)
        {
            RecordFailure(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind);
            await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
            return;
        }
        catch (Exception exception)
        {
            RecordFailure(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind);
            await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
            return;
        }

        await context.MarkAsSentAsync(entry.Id, CancellationToken.None).ConfigureAwait(false);
    }

    private static bool ShouldAddAsContentHeader(HttpRequestMessage request, KeyValuePair<string, string> header)
    {
        return !request.Headers.TryAddWithoutValidation(header.Key, header.Value);
    }

    private static void AddHeader(HttpRequestMessage request, HttpContent content, KeyValuePair<string, string> header)
    {
        if (string.Equals(header.Key, "Content-Type", StringComparison.OrdinalIgnoreCase)
            || string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (ShouldAddAsContentHeader(request, header))
        {
            content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
    }

    private static Dictionary<string, string> RegenerateSigningHeaders(
        AshlarSecurityEventWebhookOutboxEntry entry,
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        Dictionary<string, string>? persistedHeaders,
        Uri uri)
    {
        var endpoint = context.WebhookOptions.Endpoints.FirstOrDefault(candidate =>
            string.Equals(candidate.Name, entry.EndpointName, StringComparison.Ordinal));
        if (endpoint is null)
        {
            throw new InvalidOperationException($"Ashlar security event webhook endpoint configuration for '{entry.EndpointName}' is unavailable.");
        }

        var headers = persistedHeaders is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : CreateCaseInsensitiveHeaders(persistedHeaders);
        EnsureBaseHeaders(headers, entry);

        AshlarSecurityEventWebhookDeliveryFactory.AddSigningHeaders(
            headers,
            entry.EndpointName,
            endpoint.SharedSecret,
            endpoint.AllowUnsigned,
            entry.EventId,
            entry.OccurredAt,
            uri,
            entry.Body,
            context.TimeProvider.GetUtcNow());
        return headers;
    }

    private static Dictionary<string, string> CreateCaseInsensitiveHeaders(Dictionary<string, string> headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            // Persisted JSON may contain duplicate header names with different casing.
            result[header.Key] = header.Value;
        }

        return result;
    }

    private static void EnsureBaseHeaders(Dictionary<string, string> headers, AshlarSecurityEventWebhookOutboxEntry entry)
    {
        headers["X-Ashlar-Event-Id"] = entry.EventId.ToString("D");
        headers["X-Ashlar-Event-Type"] = entry.EventType;
        headers["X-Ashlar-Webhook-Endpoint"] = entry.EndpointName;
        headers[AshlarSecurityEventWebhookSignature.EventTimestampHeaderName] = entry.OccurredAt.ToString("O");
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
        AshlarSecurityEventWebhookOutboxEntry entry,
        long start)
    {
        Record(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome, null);
    }

    private static void RecordFailure(
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        AshlarSecurityEventWebhookOutboxEntry entry,
        long start,
        string failureKind)
    {
        Record(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome, failureKind);
    }

    private static void Record(
        AshlarSecurityEventWebhookOutboxDispatchContext context,
        AshlarSecurityEventWebhookOutboxEntry entry,
        long start,
        string outcome,
        string? failureKind)
    {
        try
        {
            var observer = context.DeliveryObserver ?? NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance;
            observer.RecordDeliveryAttempt(new AshlarSecurityEventWebhookDeliveryTelemetry(
                AshlarSecurityEventWebhookDeliveryTelemetry.DurableOutboxDeliveryMode,
                entry.EventType,
                entry.EndpointName,
                outcome,
                failureKind,
                Stopwatch.GetElapsedTime(start)));
        }
        catch (Exception)
        {
            // Telemetry is best-effort and must never change webhook delivery behavior.
        }
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
