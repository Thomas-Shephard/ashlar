using System.Net.Http.Headers;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Webhooks.SecurityEvents;

internal sealed class AshlarSecurityEventWebhookSender : IAshlarSecurityEventWebhookSender
{
    internal const string SignatureHeaderName = AshlarSecurityEventWebhookSignature.SignatureHeaderName;

    private static readonly Action<ILogger, string, Guid, string, int, Exception?> WebhookEndpointReturnedNonSuccess =
        LoggerMessage.Define<string, Guid, string, int>(
            LogLevel.Warning,
            new EventId(2000, nameof(WebhookEndpointReturnedNonSuccess)),
            "Ashlar security event webhook endpoint returned a non-success response. Endpoint={EndpointName} EventId={EventId} EventType={EventType} StatusCode={StatusCode}");

    private readonly AshlarSecurityEventWebhookTransport _transport;
    private readonly ILogger<AshlarSecurityEventWebhookSender> _logger;
    private readonly IAshlarSecurityEventWebhookDeliveryObserver _observer;
    private readonly AshlarSecurityEventWebhookDestinationValidator _destinationValidator;

    private static readonly Action<ILogger, string, Guid, string, string, Exception?> WebhookEndpointDestinationRejected =
        LoggerMessage.Define<string, Guid, string, string>(
            LogLevel.Warning,
            new EventId(2001, nameof(WebhookEndpointDestinationRejected)),
            "Ashlar security event webhook endpoint destination was rejected. Endpoint={EndpointName} EventId={EventId} EventType={EventType} Reason={Reason}");

    public AshlarSecurityEventWebhookSender(
        AshlarSecurityEventWebhookTransport transport,
        ILogger<AshlarSecurityEventWebhookSender>? logger = null,
        IAshlarSecurityEventWebhookDeliveryObserver? observer = null,
        AshlarSecurityEventWebhookDestinationValidator? destinationValidator = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(destinationValidator);

        _transport = transport;
        _logger = logger ?? NullLogger<AshlarSecurityEventWebhookSender>.Instance;
        _observer = observer ?? NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance;
        _destinationValidator = destinationValidator;
    }

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookSendResult> SendAsync(
        AshlarSecurityEventWebhookDelivery delivery,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(delivery);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(delivery.Timeout);

        var start = Stopwatch.GetTimestamp();
        try
        {
            var destinationValidation = await _destinationValidator.ValidateAsync(delivery.Uri, timeout.Token).ConfigureAwait(false);
            if (!destinationValidation.IsValid)
            {
                LogDestinationRejected(delivery, destinationValidation);
                RecordFailure(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind);
                return AshlarSecurityEventWebhookSendResult.DestinationRejected;
            }

            using var request = CreateRequest(delivery);
            using var response = await _transport.SendAsync(request, timeout.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                LogEndpointNonSuccess(delivery, response);
                RecordFailure(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind);
                return AshlarSecurityEventWebhookSendResult.DeliveryFailed;
            }

            RecordSuccess(delivery, start);
            return AshlarSecurityEventWebhookSendResult.Sent;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            RecordFailure(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.TimeoutFailureKind);
            throw;
        }
        catch (OperationCanceledException)
        {
            RecordFailure(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.CanceledFailureKind);
            throw;
        }
        catch
        {
            RecordFailure(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.ExceptionFailureKind);
            throw;
        }
    }

    private static HttpRequestMessage CreateRequest(AshlarSecurityEventWebhookDelivery delivery)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, delivery.Uri)
        {
            Content = new ReadOnlyMemoryContent(delivery.Body)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        foreach (var header in delivery.Headers)
        {
            request.Headers.Add(header.Key, header.Value);
        }

        return request;
    }

    private void LogEndpointNonSuccess(AshlarSecurityEventWebhookDelivery delivery, HttpResponseMessage response)
    {
        WebhookEndpointReturnedNonSuccess(
            _logger,
            delivery.EndpointName,
            delivery.Payload.Id,
            delivery.Payload.EventType,
            (int)response.StatusCode,
            null);
    }

    private void LogDestinationRejected(
        AshlarSecurityEventWebhookDelivery delivery,
        AshlarSecurityEventWebhookDestinationValidationResult validation)
    {
        WebhookEndpointDestinationRejected(
            _logger,
            delivery.EndpointName,
            delivery.Payload.Id,
            delivery.Payload.EventType,
            validation.FailureReason,
            null);
    }

    private void RecordSuccess(AshlarSecurityEventWebhookDelivery delivery, long start)
    {
        Record(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.SuccessOutcome, null);
    }

    private void RecordFailure(AshlarSecurityEventWebhookDelivery delivery, long start, string failureKind)
    {
        Record(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.FailureOutcome, failureKind);
    }

    private void Record(AshlarSecurityEventWebhookDelivery delivery, long start, string outcome, string? failureKind)
    {
        try
        {
            _observer.RecordDeliveryAttempt(new AshlarSecurityEventWebhookDeliveryTelemetry(
                AshlarSecurityEventWebhookDeliveryTelemetry.BestEffortDeliveryMode,
                delivery.Payload.EventType,
                delivery.EndpointName,
                outcome,
                failureKind,
                Stopwatch.GetElapsedTime(start)));
        }
        catch (Exception)
        {
            // Telemetry is best-effort and must never change webhook delivery behavior.
        }
    }
}
