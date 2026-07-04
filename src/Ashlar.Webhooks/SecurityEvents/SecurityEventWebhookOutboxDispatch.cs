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
    /// Gets the security event outcome.
    /// </summary>
    public required string Outcome { get; init; }

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
/// <param name="MarkAsSentAsync">The callback that persists successful delivery state and returns whether the row was updated.</param>
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
    Func<Guid, CancellationToken, Task<bool>> MarkAsSentAsync,
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
    /// <summary>
    /// Maximum number of characters persisted for safe webhook outbox failure details.
    /// </summary>
    public const int MaxPersistedFailureDetailLength = 128;

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
    /// <param name="cancellationToken">A token that can cancel the current send attempt.</param>
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
                var exception = new HttpRequestException(null, null, response.StatusCode);
                RecordFailure(context, entry, start, AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind);
                await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
                return;
            }
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

        if (!await context.MarkAsSentAsync(entry.Id, CancellationToken.None).ConfigureAwait(false))
        {
            return;
        }

        RecordSuccess(context, entry, start);
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
            new AshlarSecurityEventWebhookSigningRequest
            {
                EndpointName = entry.EndpointName,
                SharedSecret = endpoint.SharedSecret,
                AllowUnsigned = endpoint.AllowUnsigned,
                EventId = entry.EventId,
                OccurredAt = entry.OccurredAt,
                Uri = uri,
                Body = entry.Body,
                SignatureTimestamp = context.TimeProvider.GetUtcNow()
            });
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
        headers["X-Ashlar-Event-Outcome"] = GetRequiredOutcome(entry.Outcome);
        headers["X-Ashlar-Webhook-Endpoint"] = entry.EndpointName;
        headers[AshlarSecurityEventWebhookSignature.EventTimestampHeaderName] = entry.OccurredAt.ToString("O");
    }

    private static string GetRequiredOutcome(string? outcome)
    {
        if (string.IsNullOrWhiteSpace(outcome))
        {
            throw new InvalidOperationException("Durable security event webhook entry must contain a valid outcome.");
        }

        if (!AshlarSecurityEventWebhookHeaderValues.IsSafe(outcome))
        {
            throw new InvalidOperationException("Durable security event webhook entry outcome must not contain line breaks.");
        }

        return outcome;
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
        var lastError = AshlarSecurityEventWebhookOutboxFailureSummary.FromException(exception).ToPersistedString();

        return new AshlarSecurityEventWebhookOutboxFailureUpdate(
            nextAttemptCount,
            isFinalFailure ? now : null,
            isFinalFailure ? now : now.AddTicks((long)delayTicks),
            lastError);
    }
}

/// <summary>
/// Safe, bounded security event webhook delivery failure categories persisted in durable outbox state.
/// </summary>
public enum AshlarSecurityEventWebhookOutboxFailureKind
{
    /// <summary>
    /// The endpoint returned a non-success HTTP status code.
    /// </summary>
    HttpStatus,

    /// <summary>
    /// The delivery attempt timed out.
    /// </summary>
    Timeout,

    /// <summary>
    /// The delivery attempt was canceled.
    /// </summary>
    Canceled,

    /// <summary>
    /// The transport failed before a response was received.
    /// </summary>
    TransportError,

    /// <summary>
    /// The destination safety policy rejected the webhook endpoint.
    /// </summary>
    UnsafeDestination,

    /// <summary>
    /// The failure did not match a more specific safe category.
    /// </summary>
    Unknown
}

/// <summary>
/// Safe operational summary for a security event webhook delivery failure.
/// </summary>
/// <param name="Kind">The fixed failure category.</param>
/// <param name="StatusCode">The HTTP status code when safely available.</param>
/// <param name="Reason">A fixed safe reason string.</param>
public sealed record AshlarSecurityEventWebhookOutboxFailureSummary(
    AshlarSecurityEventWebhookOutboxFailureKind Kind,
    int? StatusCode,
    string Reason)
{
    private const string HttpStatusReason = "non_success_status";
    private const string TimeoutReason = "delivery_timeout";
    private const string CanceledReason = "delivery_canceled";
    private const string TransportErrorReason = "transport_error";
    private const string UnsafeDestinationReason = "unsafe_destination";
    private const string UnknownReason = "unknown_failure";

    /// <summary>
    /// Creates a safe failure summary from a dispatch exception without retaining exception text.
    /// </summary>
    /// <param name="exception">The dispatch exception.</param>
    /// <returns>The safe failure summary.</returns>
    public static AshlarSecurityEventWebhookOutboxFailureSummary FromException(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        return exception switch
        {
            HttpRequestException { StatusCode: { } statusCode } => new(AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus, (int)statusCode, HttpStatusReason),
            OperationCanceledException => new(AshlarSecurityEventWebhookOutboxFailureKind.Timeout, null, TimeoutReason),
            AshlarSecurityEventWebhookUnsafeDestinationException => new(AshlarSecurityEventWebhookOutboxFailureKind.UnsafeDestination, null, UnsafeDestinationReason),
            HttpRequestException => new(AshlarSecurityEventWebhookOutboxFailureKind.TransportError, null, TransportErrorReason),
            _ => new(AshlarSecurityEventWebhookOutboxFailureKind.Unknown, null, UnknownReason)
        };
    }

    /// <summary>
    /// Creates a safe failure summary for an externally canceled dispatch attempt.
    /// </summary>
    /// <returns>The safe canceled summary.</returns>
    public static AshlarSecurityEventWebhookOutboxFailureSummary Canceled()
    {
        return new AshlarSecurityEventWebhookOutboxFailureSummary(AshlarSecurityEventWebhookOutboxFailureKind.Canceled, null, CanceledReason);
    }

    /// <summary>
    /// Formats the summary for durable storage using only fixed tokens and optional numeric status code.
    /// </summary>
    /// <returns>The safe persisted failure detail.</returns>
    public string ToPersistedString()
    {
        var kind = Kind switch
        {
            AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus => "http_status",
            AshlarSecurityEventWebhookOutboxFailureKind.Timeout => "timeout",
            AshlarSecurityEventWebhookOutboxFailureKind.Canceled => "canceled",
            AshlarSecurityEventWebhookOutboxFailureKind.TransportError => "transport_error",
            AshlarSecurityEventWebhookOutboxFailureKind.UnsafeDestination => "unsafe_destination",
            _ => "unknown"
        };
        var reason = GetSafeReason(Kind, Reason);
        var value = TryGetSafeStatusCode(out var statusCode)
            ? $"kind={kind};status={statusCode};reason={reason}"
            : $"kind={kind};reason={reason}";
        return value;
    }

    private bool TryGetSafeStatusCode(out int statusCode)
    {
        statusCode = 0;
        if (Kind != AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus || !StatusCode.HasValue)
        {
            return false;
        }

        statusCode = StatusCode.Value;
        return statusCode >= 100 && statusCode <= 599;
    }

    private static string GetSafeReason(AshlarSecurityEventWebhookOutboxFailureKind kind, string reason)
    {
        return kind switch
        {
            AshlarSecurityEventWebhookOutboxFailureKind.HttpStatus when reason == HttpStatusReason => reason,
            AshlarSecurityEventWebhookOutboxFailureKind.Timeout when reason == TimeoutReason => reason,
            AshlarSecurityEventWebhookOutboxFailureKind.Canceled when reason == CanceledReason => reason,
            AshlarSecurityEventWebhookOutboxFailureKind.TransportError when reason == TransportErrorReason => reason,
            AshlarSecurityEventWebhookOutboxFailureKind.UnsafeDestination when reason == UnsafeDestinationReason => reason,
            AshlarSecurityEventWebhookOutboxFailureKind.Unknown when reason == UnknownReason => reason,
            _ => UnknownReason
        };
    }
}

/// <summary>
/// Represents durable state changes for a failed security event webhook dispatch attempt.
/// </summary>
/// <param name="AttemptCount">The updated attempt count.</param>
/// <param name="FailedAt">The terminal failure timestamp, if the entry exhausted retry attempts.</param>
/// <param name="AvailableAt">The next time the entry is eligible for dispatch.</param>
/// <param name="LastError">The safe bounded operational failure summary to persist, never a raw transport exception.</param>
public sealed record AshlarSecurityEventWebhookOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);
