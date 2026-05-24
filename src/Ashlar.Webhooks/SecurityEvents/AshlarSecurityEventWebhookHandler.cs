using Ashlar.Auditing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Delivers Ashlar security events to configured webhook endpoints on a best-effort basis.
/// </summary>
public sealed class AshlarSecurityEventWebhookHandler : ISecurityEventHandler
{
    private static readonly Action<ILogger, string, Guid, string, Exception?> WebhookEndpointFailed =
        LoggerMessage.Define<string, Guid, string>(
            LogLevel.Warning,
            new EventId(2001, nameof(WebhookEndpointFailed)),
            "Ashlar security event webhook endpoint failed. Endpoint={EndpointName} EventId={EventId} EventType={EventType}");

    private readonly AshlarSecurityEventWebhookDeliveryFactory _deliveryFactory;
    private readonly IAshlarSecurityEventWebhookSender _sender;
    private readonly ILogger<AshlarSecurityEventWebhookHandler> _logger;

    /// <summary>
    /// Initializes a new instance of the security event webhook handler class.
    /// </summary>
    /// <param name="deliveryFactory">The delivery factory.</param>
    /// <param name="sender">The webhook sender.</param>
    /// <param name="logger">The logger value.</param>
    public AshlarSecurityEventWebhookHandler(
        AshlarSecurityEventWebhookDeliveryFactory deliveryFactory,
        IAshlarSecurityEventWebhookSender sender,
        ILogger<AshlarSecurityEventWebhookHandler>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(deliveryFactory);
        ArgumentNullException.ThrowIfNull(sender);

        _deliveryFactory = deliveryFactory;
        _sender = sender;
        _logger = logger ?? NullLogger<AshlarSecurityEventWebhookHandler>.Instance;
    }

    /// <summary>
    /// Sends the security event to configured webhook endpoints.
    /// </summary>
    /// <param name="securityEvent">The security event value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task representing webhook delivery.</returns>
    public async Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        cancellationToken.ThrowIfCancellationRequested();

        var deliveries = _deliveryFactory.CreateDeliveries(securityEvent);
        var tasks = deliveries.Select(delivery => SendDeliverySafelyAsync(delivery, cancellationToken));

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task SendDeliverySafelyAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken)
    {
        try
        {
            await _sender.SendAsync(delivery, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            LogEndpointFailure(delivery, exception);
        }
    }

    private void LogEndpointFailure(AshlarSecurityEventWebhookDelivery delivery, Exception exception)
    {
        WebhookEndpointFailed(_logger, delivery.EndpointName, delivery.Payload.Id, delivery.Payload.EventType, exception);
    }
}
