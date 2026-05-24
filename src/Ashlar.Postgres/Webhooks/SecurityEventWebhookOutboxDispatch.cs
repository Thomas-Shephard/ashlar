using System.Net.Http.Headers;
using System.Text.Json;

namespace Ashlar.Postgres.Webhooks;

internal sealed class SecurityEventWebhookOutboxEntry
{
    public Guid Id { get; init; }
    public required string Uri { get; init; }
    public required byte[] Body { get; init; }
    public required string Headers { get; init; }
    public long TimeoutMs { get; init; }
    public int AttemptCount { get; init; }
}

internal static class SecurityEventWebhookOutboxDispatch
{
    private const int MaxLastErrorLength = 1000;

    public static HttpRequestMessage MapToHttpRequest(SecurityEventWebhookOutboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var request = new HttpRequestMessage(HttpMethod.Post, entry.Uri);
        request.Content = new ReadOnlyMemoryContent(entry.Body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers);
        if (headers != null)
        {
            foreach (var header in headers.Where(header => ShouldAddAsContentHeader(request, header)))
            {
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return request;
    }

    private static bool ShouldAddAsContentHeader(HttpRequestMessage request, KeyValuePair<string, string> header)
    {
        return !request.Headers.TryAddWithoutValidation(header.Key, header.Value);
    }

    public static WebhookOutboxFailureUpdate CreateFailureUpdate(
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

        return new WebhookOutboxFailureUpdate(
            nextAttemptCount,
            isFinalFailure ? now : null,
            isFinalFailure ? now : now.AddTicks((long)delayTicks),
            lastError);
    }
}

internal sealed record WebhookOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);
