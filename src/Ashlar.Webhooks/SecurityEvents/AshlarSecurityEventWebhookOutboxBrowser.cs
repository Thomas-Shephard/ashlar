namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Provides safe read-only browsing for durable security event webhook outbox deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookOutboxBrowser
{
    /// <summary>
    /// Lists safe security event webhook outbox delivery summaries.
    /// </summary>
    /// <param name="request">The browse request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The matching outbox delivery summaries.</returns>
    Task<AshlarSecurityEventWebhookOutboxBrowseResult> ListAsync(
        AshlarSecurityEventWebhookOutboxBrowseRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Request for safe security event webhook outbox browsing.
/// </summary>
public sealed record AshlarSecurityEventWebhookOutboxBrowseRequest
{
    /// <summary>
    /// Maximum number of deliveries that can be requested.
    /// </summary>
    public const int MaximumLimit = 100;

    /// <summary>
    /// Gets the default number of deliveries returned.
    /// </summary>
    public const int DefaultLimit = 50;

    /// <summary>
    /// Gets the requested status filter. Empty means all non-sent browseable statuses.
    /// </summary>
    public IReadOnlySet<AshlarSecurityEventWebhookOutboxStatus>? Statuses { get; init; }

    /// <summary>
    /// Gets the maximum number of deliveries to return.
    /// </summary>
    public int Limit { get; init; } = DefaultLimit;

    /// <summary>
    /// Gets the number of deliveries to skip.
    /// </summary>
    public int Offset { get; init; }
}

/// <summary>
/// Safe outbox delivery status values exposed for browsing.
/// </summary>
public enum AshlarSecurityEventWebhookOutboxStatus
{
    /// <summary>
    /// The delivery is available for a retry and is not actively locked.
    /// </summary>
    Pending,

    /// <summary>
    /// The delivery is waiting for a future retry time.
    /// </summary>
    Scheduled,

    /// <summary>
    /// The delivery is currently locked by a dispatcher.
    /// </summary>
    Locked,

    /// <summary>
    /// The delivery has an expired dispatcher lock.
    /// </summary>
    ExpiredLock,

    /// <summary>
    /// The delivery has reached terminal failure.
    /// </summary>
    Failed
}

/// <summary>
/// Safe summary of a durable security event webhook outbox delivery.
/// </summary>
/// <param name="DeliveryId">The delivery id value.</param>
/// <param name="EndpointName">The endpoint name value.</param>
/// <param name="EventId">The event id value.</param>
/// <param name="EventType">The event type value.</param>
/// <param name="Outcome">The outcome value.</param>
/// <param name="Status">The derived delivery status.</param>
/// <param name="AttemptCount">The attempted delivery count.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastAttemptAt">The last attempt timestamp.</param>
/// <param name="FailedAt">The terminal failure timestamp.</param>
/// <param name="LastErrorSummary">The truncated safe error summary.</param>
public sealed record AshlarSecurityEventWebhookOutboxDeliverySummary(
    Guid DeliveryId,
    string? EndpointName,
    Guid EventId,
    string? EventType,
    string? Outcome,
    AshlarSecurityEventWebhookOutboxStatus Status,
    int AttemptCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset AvailableAt,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? FailedAt,
    string? LastErrorSummary);

/// <summary>
/// Paged security event webhook outbox browsing result.
/// </summary>
/// <param name="Deliveries">The deliveries value.</param>
/// <param name="Limit">The limit value.</param>
/// <param name="Offset">The offset value.</param>
/// <param name="HasMore">Whether another page may exist.</param>
public sealed record AshlarSecurityEventWebhookOutboxBrowseResult(
    IReadOnlyList<AshlarSecurityEventWebhookOutboxDeliverySummary> Deliveries,
    int Limit,
    int Offset,
    bool HasMore);

/// <summary>
/// Shared safe mapping and validation helpers for security event webhook outbox browsing.
/// </summary>
public static class AshlarSecurityEventWebhookOutboxBrowser
{
    /// <summary>
    /// Maximum number of characters exposed from stored last_error.
    /// </summary>
    public const int MaxLastErrorSummaryLength = 256;

    /// <summary>
    /// Gets all browseable non-sent statuses.
    /// </summary>
    public static IReadOnlySet<AshlarSecurityEventWebhookOutboxStatus> DefaultStatuses { get; } =
        Enum.GetValues<AshlarSecurityEventWebhookOutboxStatus>().ToHashSet();

    /// <summary>
    /// Validates a browser request.
    /// </summary>
    /// <param name="request">The request value.</param>
    public static void ValidateRequest(AshlarSecurityEventWebhookOutboxBrowseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Limit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Limit, "Limit must be greater than zero.");
        }

        if (request.Limit > AshlarSecurityEventWebhookOutboxBrowseRequest.MaximumLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Limit, "Limit cannot exceed the maximum limit.");
        }

        if (request.Offset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Offset, "Offset cannot be negative.");
        }

        var unsupportedStatus = request.Statuses?.Where(static status => !Enum.IsDefined(status)).Cast<AshlarSecurityEventWebhookOutboxStatus?>().FirstOrDefault();
        if (unsupportedStatus.HasValue)
        {
            throw new ArgumentOutOfRangeException(nameof(request), unsupportedStatus.Value, "Status is not supported.");
        }
    }

    /// <summary>
    /// Gets the status filter for a request.
    /// </summary>
    /// <param name="request">The request value.</param>
    /// <returns>The effective status set.</returns>
    public static IReadOnlySet<AshlarSecurityEventWebhookOutboxStatus> GetStatuses(AshlarSecurityEventWebhookOutboxBrowseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Statuses is { Count: > 0 } ? request.Statuses : DefaultStatuses;
    }

    /// <summary>
    /// Sanitizes a stored header-safe text value for display.
    /// </summary>
    /// <param name="value">The stored value.</param>
    /// <returns>The safe display value, or <see langword="null" /> when malformed.</returns>
    public static string? SanitizeSafeText(string? value)
    {
        return string.IsNullOrWhiteSpace(value) || !AshlarSecurityEventWebhookHeaderValues.IsSafe(value) ? null : value;
    }

    /// <summary>
    /// Creates a conservative error summary from stored last_error.
    /// </summary>
    /// <param name="lastError">The stored last_error value.</param>
    /// <returns>The safe error summary.</returns>
    public static string? CreateLastErrorSummary(string? lastError)
    {
        if (lastError is null)
        {
            return null;
        }

        var summary = lastError.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (summary.Length > MaxLastErrorSummaryLength)
        {
            summary = summary[..MaxLastErrorSummaryLength];
        }

        return summary;
    }

    /// <summary>
    /// Parses a provider-derived status name defensively.
    /// </summary>
    /// <param name="status">The provider-derived status name.</param>
    /// <returns>The status value.</returns>
    public static AshlarSecurityEventWebhookOutboxStatus ParseStatus(string? status)
    {
        return Enum.TryParse<AshlarSecurityEventWebhookOutboxStatus>(status, ignoreCase: false, out var parsed)
            && Enum.IsDefined(parsed)
            ? parsed
            : AshlarSecurityEventWebhookOutboxStatus.Pending;
    }
}
