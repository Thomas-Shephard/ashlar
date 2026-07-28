using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Features.Administration;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Models.Administration;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Provides global operational administration operations for failed durable security event webhook outbox deliveries.
/// </summary>
public interface IAshlarSecurityEventWebhookOutboxOperations
{
    /// <summary>
    /// Makes a terminal failed delivery dispatchable immediately.
    /// </summary>
    /// <param name="request">Delivery id, authenticated actor context, and explicit global operational scope required for the retry mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable retry outcome with only header-safe event metadata.</returns>
    Task<AshlarSecurityEventWebhookOutboxOperationResult> RetryAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a terminal failed delivery as discarded.
    /// </summary>
    /// <param name="request">Delivery id, authenticated actor context, and explicit global operational scope required for the discard mutation.</param>
    /// <param name="cancellationToken">A token that can cancel the mutation before it is committed.</param>
    /// <returns>The stable discard outcome with only header-safe event metadata.</returns>
    Task<AshlarSecurityEventWebhookOutboxOperationResult> DiscardAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Request for a global operational administration operation on the durable security event webhook outbox.
/// </summary>
/// <param name="DeliveryId">The durable outbox delivery id.</param>
/// <param name="Actor">The authenticated actor context.</param>
/// <param name="Scope">The explicit global operational administration scope.</param>
public sealed record AshlarSecurityEventWebhookOutboxOperationRequest(
    Guid DeliveryId,
    AccountSecurityActorContext Actor,
    OperationalAdministrationScope Scope);

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
/// <param name="sessions">The authentication-session repository.</param>
/// <param name="authorizer">The host operation authorizer.</param>
/// <param name="auditSink">The durable audit sink.</param>
public abstract class AshlarSecurityEventWebhookOutboxOperationsBase(
    TimeProvider timeProvider,
    ISecurityEventSink securityEventSink,
    AshlarDurableTransactionProvider transactionProvider,
    IAuthenticationSessionRepository sessions,
    IAccountSecurityOperationAuthorizer authorizer,
    IPersistentSecurityEventSink auditSink) : IAshlarSecurityEventWebhookOutboxOperations
{
    private readonly ISecurityEventSink _securityEventSink = securityEventSink ?? throw new ArgumentNullException(nameof(securityEventSink));
    private readonly AshlarDurableTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly AccountSecurityOperationBoundary _boundary = new(sessions, authorizer, auditSink, timeProvider,
        IAccountSecurityAdministrationService.ProofPurpose, "security_event_webhook.operation");

    /// <summary>
    /// Gets the time provider.
    /// </summary>
    protected TimeProvider TimeProvider { get; } = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookOutboxOperationResult> RetryAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            request,
            AshlarSecurityEventWebhookOutboxOperationStatus.Retried,
            AshlarSecurityEventTypes.SecurityEventWebhookOutboxDeliveryRetried,
            RetryFailedAsync,
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookOutboxOperationResult> DiscardAsync(
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteAsync(
            request,
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
        AshlarSecurityEventWebhookOutboxOperationStatus successStatus,
        string auditEventType,
        Func<Guid, CancellationToken, Task<AshlarSecurityEventWebhookOutboxOperationState?>> applyAsync,
        CancellationToken cancellationToken)
    {
        AshlarSecurityEventWebhookOutboxOperations.ValidateRequest(request);
        var operation = successStatus == AshlarSecurityEventWebhookOutboxOperationStatus.Retried
            ? AccountSecurityOperation.RetrySecurityEventWebhookDelivery
            : AccountSecurityOperation.DiscardSecurityEventWebhookDelivery;
        if (!await _boundary.AuthorizeAsync(request.Actor, null, true, Guid.Empty, operation, cancellationToken).ConfigureAwait(false))
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
            request,
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
    public static void ValidateRequest(AshlarSecurityEventWebhookOutboxOperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        AshlarSecurityEventWebhookOutboxBrowser.ValidateScope(request.Scope);
        if (request.DeliveryId == Guid.Empty)
        {
            throw new ArgumentException("Delivery ID cannot be empty.", nameof(request));
        }

        ArgumentNullException.ThrowIfNull(request.Actor);
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
        AshlarSecurityEventWebhookOutboxOperationRequest request,
        AshlarSecurityEventWebhookOutboxOperationResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);

        await SecurityEventAuditEmission.RecordCompletedOperationAsync(
            sink,
            timeProvider,
            eventType,
            request.Actor.Audit,
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
