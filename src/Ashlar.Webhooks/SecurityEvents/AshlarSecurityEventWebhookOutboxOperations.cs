using Ashlar.Auditing;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Provides safe state-changing operations for failed durable security event webhook outbox deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookOutboxOperations
{
    /// <summary>
    /// Makes a terminal failed delivery dispatchable immediately.
    /// </summary>
    /// <param name="request">The retry request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AshlarSecurityEventWebhookOutboxOperationResult> RetryAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a terminal failed delivery as discarded.
    /// </summary>
    /// <param name="request">The discard request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AshlarSecurityEventWebhookOutboxOperationResult> DiscardAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Request for a manual durable security event webhook outbox operation.
/// </summary>
/// <param name="DeliveryId">The durable outbox delivery id.</param>
/// <param name="Audit">The required audit context.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationRequest(
    Guid DeliveryId,
    AuditContext Audit);

/// <summary>
/// Safe result statuses for manual durable security event webhook outbox operations.
/// </summary>
public enum AshlarSecurityEventWebhookOutboxOperationStatus
{
    /// <summary>
    /// The delivery was moved back to dispatchable retry state.
    /// </summary>
    Retried,

    /// <summary>
    /// The delivery was marked discarded.
    /// </summary>
    Discarded,

    /// <summary>
    /// No delivery exists for the requested id.
    /// </summary>
    NotFound,

    /// <summary>
    /// The delivery exists but is not in terminal failed state.
    /// </summary>
    NotFailed,

    /// <summary>
    /// The delivery was already discarded.
    /// </summary>
    AlreadyDiscarded,

    /// <summary>
    /// The operation could not complete after validating the request.
    /// </summary>
    Failed
}

/// <summary>
/// Safe result for a manual durable security event webhook outbox operation.
/// </summary>
/// <param name="Status">The operation status.</param>
/// <param name="DeliveryId">The delivery id value.</param>
/// <param name="EndpointName">The safe endpoint name value.</param>
/// <param name="EventId">The security event id value.</param>
/// <param name="EventType">The safe security event type value.</param>
/// <param name="Outcome">The safe security event outcome value.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationResult(
    AshlarSecurityEventWebhookOutboxOperationStatus Status,
    Guid DeliveryId,
    string? EndpointName = null,
    Guid? EventId = null,
    string? EventType = null,
    string? Outcome = null);

/// <summary>
/// Safe stored metadata used to classify and report manual durable outbox operations.
/// </summary>
/// <param name="DeliveryId">The delivery id value.</param>
/// <param name="EndpointName">The safe endpoint name value.</param>
/// <param name="EventId">The security event id value.</param>
/// <param name="EventType">The safe security event type value.</param>
/// <param name="Outcome">The safe security event outcome value.</param>
/// <param name="IsDiscarded">A value indicating whether the delivery is already discarded.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationState(
    Guid DeliveryId,
    string? EndpointName,
    Guid EventId,
    string? EventType,
    string? Outcome,
    bool IsDiscarded);

/// <summary>
/// Provider-specific callbacks and dependencies for a manual durable outbox operation.
/// </summary>
/// <param name="SuccessStatus">The status to return when the state change is applied.</param>
/// <param name="AuditEventType">The audit event type to emit when the state change is applied.</param>
/// <param name="ApplyAsync">The conditional state-changing persistence callback.</param>
/// <param name="LoadAsync">The persistence callback used to classify no-op results.</param>
/// <param name="SecurityEventSink">The security event sink.</param>
/// <param name="TimeProvider">The time provider.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationContext(
    AshlarSecurityEventWebhookOutboxOperationStatus SuccessStatus,
    string AuditEventType,
    Func<Guid, CancellationToken, Task<AshlarSecurityEventWebhookOutboxOperationState?>> ApplyAsync,
    Func<Guid, CancellationToken, Task<AshlarSecurityEventWebhookOutboxOperationState?>> LoadAsync,
    ISecurityEventSink SecurityEventSink,
    TimeProvider TimeProvider);

/// <summary>
/// Shared validation and safe audit helpers for manual webhook outbox operations.
/// </summary>
public static class AshlarSecurityEventWebhookOutboxOperations
{
    /// <summary>
    /// Validates a manual operation request.
    /// </summary>
    /// <param name="request">The request value.</param>
    public static void ValidateRequest(AshlarSecurityEventWebhookOutboxOperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.DeliveryId == Guid.Empty)
        {
            throw new ArgumentException("Delivery ID cannot be empty.", nameof(request));
        }

        ArgumentNullException.ThrowIfNull(request.Audit);
    }

    /// <summary>
    /// Creates a safe operation result from stored outbox metadata.
    /// </summary>
    /// <param name="status">The operation status.</param>
    /// <param name="deliveryId">The delivery id.</param>
    /// <param name="endpointName">The stored endpoint name.</param>
    /// <param name="eventId">The stored event id.</param>
    /// <param name="eventType">The stored event type.</param>
    /// <param name="outcome">The stored outcome.</param>
    /// <returns>The safe operation result.</returns>
    public static AshlarSecurityEventWebhookOutboxOperationResult CreateResult(
        AshlarSecurityEventWebhookOutboxOperationStatus status,
        Guid deliveryId,
        string? endpointName = null,
        Guid? eventId = null,
        string? eventType = null,
        string? outcome = null)
    {
        return new AshlarSecurityEventWebhookOutboxOperationResult(
            status,
            deliveryId,
            AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(endpointName),
            eventId,
            AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(eventType),
            AshlarSecurityEventWebhookOutboxBrowser.SanitizeSafeText(outcome));
    }

    /// <summary>
    /// Applies a provider-specific manual state change and classifies no-op results.
    /// </summary>
    /// <param name="request">The operation request.</param>
    /// <param name="context">The provider-specific operation context.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The safe operation result.</returns>
    public static async Task<AshlarSecurityEventWebhookOutboxOperationResult> ExecuteStateChangeAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        AshlarSecurityEventWebhookOutboxOperationContext context,
        CancellationToken cancellationToken)
    {
        ValidateRequest(request);

        var row = await context.ApplyAsync(request.DeliveryId, cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return await ClassifyNoOpAsync(request.DeliveryId, context, cancellationToken).ConfigureAwait(false);
        }

        var result = CreateResult(context.SuccessStatus, row);
        await RecordSuccessfulOperationAsync(
            context.SecurityEventSink,
            context.TimeProvider,
            context.AuditEventType,
            request,
            result,
            cancellationToken).ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Emits a fail-open audit event for a successful manual outbox operation.
    /// </summary>
    /// <param name="sink">The security event sink.</param>
    /// <param name="timeProvider">The time provider.</param>
    /// <param name="eventType">The audit event type.</param>
    /// <param name="request">The operation request.</param>
    /// <param name="result">The safe operation result.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task representing audit emission.</returns>
    public static async Task RecordSuccessfulOperationAsync(
        ISecurityEventSink sink,
        TimeProvider timeProvider,
        string eventType,
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        AshlarSecurityEventWebhookOutboxOperationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);

        try
        {
            await sink.RecordAsync(new AshlarSecurityEvent
            {
                Id = Guid.NewGuid(),
                EventType = eventType,
                OccurredAt = timeProvider.GetUtcNow(),
                ActorUserId = request.Audit.ActorUserId,
                IpAddress = request.Audit.IpAddress,
                UserAgent = request.Audit.UserAgent,
                CorrelationId = request.Audit.CorrelationId,
                Outcome = SecurityEventOutcomes.Success,
                Properties = CreateAuditProperties(result)
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Ashlar security event audit emission is fail-open.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Ashlar security event audit emission is fail-open.
        }
    }

    private static async Task<AshlarSecurityEventWebhookOutboxOperationResult> ClassifyNoOpAsync(
        Guid deliveryId,
        AshlarSecurityEventWebhookOutboxOperationContext context,
        CancellationToken cancellationToken)
    {
        var row = await context.LoadAsync(deliveryId, cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return CreateResult(AshlarSecurityEventWebhookOutboxOperationStatus.NotFound, deliveryId);
        }

        var status = row.IsDiscarded
            ? AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded
            : AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed;
        return CreateResult(status, row);
    }

    private static AshlarSecurityEventWebhookOutboxOperationResult CreateResult(
        AshlarSecurityEventWebhookOutboxOperationStatus status,
        AshlarSecurityEventWebhookOutboxOperationState row)
    {
        return CreateResult(
            status,
            row.DeliveryId,
            row.EndpointName,
            row.EventId,
            row.EventType,
            row.Outcome);
    }

    private static Dictionary<string, string> CreateAuditProperties(AshlarSecurityEventWebhookOutboxOperationResult result)
    {
        var properties = new Dictionary<string, string>
        {
            ["delivery_id"] = result.DeliveryId.ToString("D")
        };
        if (result.EndpointName != null)
        {
            properties["endpoint_name"] = result.EndpointName;
        }

        if (result.EventId.HasValue)
        {
            properties["event_id"] = result.EventId.Value.ToString("D");
        }

        if (result.EventType != null)
        {
            properties["event_type"] = result.EventType;
        }

        if (result.Outcome != null)
        {
            properties["outcome"] = result.Outcome;
        }

        return properties;
    }
}
