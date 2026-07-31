using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Features.Administration;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Models.Administration;
using Ashlar.Operational;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Provides global operational administration operations for failed durable security event webhook outbox deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookOutboxOperations
{
    /// <summary>
    /// Makes a terminal failed delivery dispatchable immediately.
    /// </summary>
    /// <param name="actor">The authenticated operator context.</param>
    /// <param name="scope">The explicit global operational scope.</param>
    /// <param name="request">Delivery id required for the retry mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable retry outcome with only header-safe event metadata.</returns>
    Task<AshlarSecurityEventWebhookOutboxOperationResult> RetryAsync(
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a terminal failed delivery as discarded.
    /// </summary>
    /// <param name="actor">The authenticated operator context.</param>
    /// <param name="scope">The explicit global operational scope.</param>
    /// <param name="request">Delivery id required for the discard mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable discard outcome with only header-safe event metadata.</returns>
    Task<AshlarSecurityEventWebhookOutboxOperationResult> DiscardAsync(
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Request for a global operational administration operation on the durable security event webhook outbox.
/// </summary>
/// <param name="DeliveryId">The durable outbox delivery id.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationRequest(
    Guid DeliveryId);

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
/// <param name="Status">Stable mutation result.</param>
/// <param name="DeliveryId">The durable outbox delivery id.</param>
/// <param name="EndpointName">The endpoint name, omitted when unavailable or malformed.</param>
/// <param name="EventId">The security event id, when available.</param>
/// <param name="EventType">The security event type, omitted when unavailable or malformed.</param>
/// <param name="Outcome">Header-safe result value, omitted when unavailable or malformed.</param>
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
/// <param name="DeliveryId">The durable outbox delivery id.</param>
/// <param name="EndpointName">Stored endpoint name used only after header-safety validation.</param>
/// <param name="EventId">The security event id.</param>
/// <param name="EventType">Stored event type used only after header-safety validation.</param>
/// <param name="Outcome">Stored event outcome used only after header-safety validation.</param>
/// <param name="IsDiscarded">A value indicating whether the delivery is already discarded.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationState(
    Guid DeliveryId,
    string? EndpointName,
    Guid EventId,
    string? EventType,
    string? Outcome,
    bool IsDiscarded);

/// <summary>
/// Shared implementation for provider-specific manual durable outbox operations.
/// </summary>
/// <param name="timeProvider">Clock used for operation audit timestamps.</param>
/// <param name="securityEventSink">Durable audit sink used for successful mutating operations. It is required so state changes and audit writes share one atomic boundary.</param>
/// <param name="transactionProvider">Ashlar-owned durable transaction composition used to commit provider mutations with their required audit writes.</param>
/// <param name="administration">Precomposed authorization and audit boundaries.</param>
public abstract class AshlarSecurityEventWebhookOutboxOperationsBase(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    AshlarDurableTransactionProvider transactionProvider,
    AshlarOperationalAdministrationContext administration) : IAshlarSecurityEventWebhookOutboxOperations
{
    private readonly ISecurityEventSink _securityEventSink = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    private readonly AshlarDurableTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly AccountSecurityOperationBoundary _boundary =
        (administration ?? throw new ArgumentNullException(nameof(administration))).MutationBoundary;

    /// <summary>
    /// Gets the time provider.
    /// </summary>
    protected TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookOutboxOperationResult> RetryAsync(
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            request,
            actor,
            scope,
            AshlarSecurityEventWebhookOutboxOperationStatus.Retried,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried,
            RetryFailedAsync,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookOutboxOperationResult> DiscardAsync(
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            request,
            actor,
            scope,
            AshlarSecurityEventWebhookOutboxOperationStatus.Discarded,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryDiscarded,
            DiscardFailedAsync,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies the provider-specific conditional retry state change.
    /// </summary>
    /// <param name="deliveryId">The delivery id.</param>
    /// <param name="cancellationToken">A token that can cancel the provider mutation.</param>
    /// <returns>The updated safe state, or <see langword="null" /> when no row changed.</returns>
    protected abstract Task<AshlarSecurityEventWebhookOutboxOperationState?> RetryFailedAsync(
        Guid deliveryId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Applies the provider-specific conditional discard state change.
    /// </summary>
    /// <param name="deliveryId">The delivery id.</param>
    /// <param name="cancellationToken">A token that can cancel the provider mutation.</param>
    /// <returns>The updated safe state, or <see langword="null" /> when no row changed.</returns>
    protected abstract Task<AshlarSecurityEventWebhookOutboxOperationState?> DiscardFailedAsync(
        Guid deliveryId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Loads provider-specific safe state for no-op classification.
    /// </summary>
    /// <param name="deliveryId">The delivery id.</param>
    /// <param name="cancellationToken">A token that can cancel the provider lookup.</param>
    /// <returns>The stored safe state, or <see langword="null" /> when the delivery does not exist.</returns>
    protected abstract Task<AshlarSecurityEventWebhookOutboxOperationState?> LoadAsync(
        Guid deliveryId,
        CancellationToken cancellationToken);

    private async Task<AshlarSecurityEventWebhookOutboxOperationResult> ExecuteAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        AccountSecurityActorContext actor,
        OperationalAdministrationScope scope,
        AshlarSecurityEventWebhookOutboxOperationStatus successStatus,
        string auditEventType,
        Func<Guid, CancellationToken, Task<AshlarSecurityEventWebhookOutboxOperationState?>> applyAsync,
        CancellationToken cancellationToken)
    {
        AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(actor, scope, request);
        var operation = successStatus == AshlarSecurityEventWebhookOutboxOperationStatus.Retried
            ? AccountSecurityOperation.RetrySecurityEventWebhookDelivery
            : AccountSecurityOperation.DiscardSecurityEventWebhookDelivery;
        if (await _boundary.AuthorizeAsync(actor, null, true, Guid.Empty, operation, cancellationToken).ConfigureAwait(false) is not null)
        {
            return AshlarSecurityEventWebhookOutboxOperations.CreateResult(AshlarSecurityEventWebhookOutboxOperationStatus.Failed, request.DeliveryId);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var row = await applyAsync(request.DeliveryId, cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return await ClassifyNoOpAsync(request.DeliveryId, cancellationToken).ConfigureAwait(false);
        }

        var result = AshlarSecurityEventWebhookOutboxOperations.CreateResult(successStatus, row);
        await AshlarSecurityEventWebhookOutboxOperations.RecordSuccessfulOperationAsync(
            _securityEventSink,
            TimeProvider,
            auditEventType,
            actor,
            result,
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

        return result;
    }

    private async Task<AshlarSecurityEventWebhookOutboxOperationResult> ClassifyNoOpAsync(
        Guid deliveryId,
        CancellationToken cancellationToken)
    {
        var row = await LoadAsync(deliveryId, cancellationToken).ConfigureAwait(false);
        if (row is null)
        {
            return AshlarSecurityEventWebhookOutboxOperations.CreateResult(
                AshlarSecurityEventWebhookOutboxOperationStatus.NotFound,
                deliveryId);
        }

        var status = row.IsDiscarded
            ? AshlarSecurityEventWebhookOutboxOperationStatus.AlreadyDiscarded
            : AshlarSecurityEventWebhookOutboxOperationStatus.NotFailed;
        return AshlarSecurityEventWebhookOutboxOperations.CreateResult(status, row);
    }
}

internal static class AshlarSecurityEventWebhookOutboxOperations
{
    public static void ValidateRequest(AccountSecurityActorContext actor, OperationalAdministrationScope scope, AshlarSecurityEventWebhookOutboxOperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(actor);
        AshlarSecurityEventWebhookOutboxBrowser.ValidateScope(scope);
        if (request.DeliveryId == Guid.Empty)
        {
            throw new ArgumentException("Delivery ID cannot be empty.", nameof(request));
        }

    }

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

    public static async Task RecordSuccessfulOperationAsync(
        ISecurityEventSink sink,
        TimeProvider timeProvider,
        string eventType,
        AccountSecurityActorContext actor,
        AshlarSecurityEventWebhookOutboxOperationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(result);

        await SecurityEventAuditEmission.RecordCompletedOperationAsync(
            sink,
            timeProvider,
            eventType,
            actor.Audit,
            CreateAuditProperties(result),
            cancellationToken).ConfigureAwait(false);
    }

    internal static AshlarSecurityEventWebhookOutboxOperationResult CreateResult(
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
