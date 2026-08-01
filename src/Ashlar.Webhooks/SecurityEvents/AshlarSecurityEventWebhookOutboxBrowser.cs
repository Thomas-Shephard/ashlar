using Ashlar.Identity.Features.Administration;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Models.Administration;
using Ashlar.Operational;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Provides global operational administration browsing for durable security event webhook outbox deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookOutboxBrowser
{
    /// <summary>
    /// Browses safe global security event webhook outbox delivery summaries.
    /// </summary>
    /// <param name="actor">The authenticated and proof-bound actor.</param>
    /// <param name="scope">The explicit global operational scope.</param>
    /// <param name="request">Paging and status filters for the read-only browse operation.</param>
    /// <param name="cancellationToken">A token that can cancel the browse operation before results are returned.</param>
    /// <returns>Matching outbox delivery summaries with destination URI, body, headers, and lock-owner values omitted.</returns>
    Task<AshlarSecurityEventWebhookOutboxBrowseResult> BrowseAsync(
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxBrowseRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>Shared authorization, paging, and audit behavior for provider-specific webhook outbox browsers.</summary>
/// <param name="administration">Precomposed authorization and audit boundaries.</param>
public abstract class AshlarSecurityEventWebhookOutboxBrowserBase(
    AshlarOperationalAdministrationContext administration) : IAshlarSecurityEventWebhookOutboxBrowser
{
    private readonly AccountSecurityOperationBoundary _boundary =
        (administration ?? throw new ArgumentNullException(nameof(administration))).ReadBoundary;

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookOutboxBrowseResult> BrowseAsync(
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxBrowseRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        AshlarSecurityEventWebhookOutboxBrowser.ValidateRequest(scope, request);
        if (await _boundary.AuthorizeAsync(actor, null, true, Guid.Empty,
                AccountSecurityOperation.BrowseSecurityEventWebhookOutbox, cancellationToken).ConfigureAwait(false) is not null)
            return new AshlarSecurityEventWebhookOutboxBrowseResult([], request.Limit, request.Offset, false);

        var rows = await LoadAsync(request, cancellationToken).ConfigureAwait(false);
        var result = new AshlarSecurityEventWebhookOutboxBrowseResult(
            rows.Take(request.Limit).ToList().AsReadOnly(),
            request.Limit,
            request.Offset,
            rows.Count > request.Limit);
        await _boundary.RecordSuccessAsync(
            actor, null, true, AccountSecurityOperation.BrowseSecurityEventWebhookOutbox).ConfigureAwait(false);
        return result;
    }

    /// <summary>Loads at most the requested page plus one sentinel row.</summary>
    /// <param name="request">The validated browse request.</param>
    /// <param name="cancellationToken">A token that can cancel provider loading.</param>
    /// <returns>The safe provider rows, including a sentinel row when another page exists.</returns>
    protected abstract Task<IReadOnlyList<AshlarSecurityEventWebhookOutboxDeliverySummary>> LoadAsync(
        AshlarSecurityEventWebhookOutboxBrowseRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Request for global operational administration browsing of the security event webhook outbox.
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
/// <param name="DeliveryId">The durable outbox delivery id.</param>
/// <param name="EndpointName">The endpoint name, omitted when unavailable or malformed.</param>
/// <param name="EventId">The security event id.</param>
/// <param name="EventType">The security event type, omitted when unavailable or malformed.</param>
/// <param name="Outcome">The security event outcome, omitted when unavailable or malformed.</param>
/// <param name="Status">The derived delivery status.</param>
/// <param name="AttemptCount">The attempted delivery count.</param>
/// <param name="CreatedAt">The creation timestamp.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastAttemptAt">The last attempt timestamp.</param>
/// <param name="FailedAt">The terminal failure timestamp.</param>
/// <param name="LastErrorSummary">Safe stored operational failure summary, not a raw transport exception.</param>
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
/// <param name="Deliveries">Safe delivery summaries returned for this page.</param>
/// <param name="Limit">Maximum number of <paramref name="Deliveries" /> requested.</param>
/// <param name="Offset">Number of <paramref name="Deliveries" /> skipped before this page.</param>
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
    private const string HttpStatusFailurePrefix = "kind=http_status;status=";
    private const string HttpStatusFailureSuffix = ";reason=non_success_status";
    private static readonly HashSet<string> CanonicalFailureSummaries =
    [
        "kind=timeout;reason=delivery_timeout",
        "kind=canceled;reason=delivery_canceled",
        "kind=transport_error;reason=transport_error",
        "kind=unsafe_destination;reason=unsafe_destination",
        "kind=unknown;reason=unknown_failure"
    ];

    /// <summary>
    /// Maximum number of characters exposed from stored safe failure details.
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
    /// <param name="scope">The explicit global operational scope.</param>
    /// <param name="request">Browse request to validate.</param>
    public static void ValidateRequest(OperationalAdministrationScope scope, AshlarSecurityEventWebhookOutboxBrowseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateScope(scope);
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

    internal static void ValidateScope(OperationalAdministrationScope scope)
    {
        if (scope != OperationalAdministrationScope.Global)
        {
            throw new ArgumentOutOfRangeException(nameof(scope), scope, "Global webhook outbox administration scope is required.");
        }
    }

    /// <summary>
    /// Gets the status filter for a request.
    /// </summary>
    /// <param name="request">Browse request whose explicit or default status set is needed.</param>
    /// <returns>The effective status set.</returns>
    public static IReadOnlySet<AshlarSecurityEventWebhookOutboxStatus> GetStatuses(AshlarSecurityEventWebhookOutboxBrowseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request.Statuses is { Count: > 0 } ? request.Statuses : DefaultStatuses;
    }

    /// <summary>
    /// Sanitizes a stored header-safe text value for display.
    /// </summary>
    /// <param name="value">Stored endpoint or event metadata.</param>
    /// <returns>The safe display value, or <see langword="null" /> when malformed.</returns>
    public static string? SanitizeSafeText(string? value)
    {
        return string.IsNullOrWhiteSpace(value) || !AshlarSecurityEventWebhookHeaderValues.IsSafe(value) ? null : value;
    }

    /// <summary>
    /// Creates a conservative error summary from stored safe failure details.
    /// </summary>
    /// <param name="lastError">Stored safe failure detail from the dispatcher.</param>
    /// <returns>The safe error summary, or <see langword="null" /> when stored detail is malformed or contains raw exception text.</returns>
    public static string? CreateLastErrorSummary(string? lastError)
    {
        var summary = lastError?.Trim();
        if (string.IsNullOrWhiteSpace(summary)
            || summary.Contains('\r', StringComparison.Ordinal)
            || summary.Contains('\n', StringComparison.Ordinal)
            || summary.Length > MaxLastErrorSummaryLength
            || !IsSafePersistedFailureDetail(summary))
        {
            return null;
        }

        return summary;
    }

    private static bool IsSafePersistedFailureDetail(string value)
    {
        if (CanonicalFailureSummaries.Contains(value))
        {
            return true;
        }

        if (!value.StartsWith(HttpStatusFailurePrefix, StringComparison.Ordinal)
            || !value.EndsWith(HttpStatusFailureSuffix, StringComparison.Ordinal))
        {
            return false;
        }

        var status = value[HttpStatusFailurePrefix.Length..^HttpStatusFailureSuffix.Length];
        if (!int.TryParse(status, out var statusCode))
        {
            return false;
        }

        return statusCode >= 100 && statusCode <= 599;
    }

    /// <summary>
    /// Parses a provider-derived status name defensively.
    /// </summary>
    /// <param name="status">The provider-derived status name.</param>
    /// <returns>The parsed status, or <see cref="AshlarSecurityEventWebhookOutboxStatus.Pending" /> for unknown values.</returns>
    public static AshlarSecurityEventWebhookOutboxStatus ParseStatus(string? status)
    {
        return Enum.TryParse<AshlarSecurityEventWebhookOutboxStatus>(status, ignoreCase: false, out var parsed)
            && Enum.IsDefined(parsed)
            ? parsed
            : AshlarSecurityEventWebhookOutboxStatus.Pending;
    }
}
