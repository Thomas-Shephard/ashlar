using System.Net.Http.Headers;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Sends prepared Ashlar security event webhook deliveries over HTTP.
/// </summary>
public sealed class AshlarSecurityEventWebhookSender : IAshlarSecurityEventWebhookSender
{
    /// <summary>
    /// Defines the named HTTP client used by Ashlar security event webhooks.
    /// </summary>
    public const string HttpClientName = "Ashlar.SecurityEventWebhooks";

    internal const string SignatureHeaderName = AshlarSecurityEventWebhookSignature.SignatureHeaderName;

    private static readonly Action<ILogger, string, Guid, string, int, Exception?> WebhookEndpointReturnedNonSuccess =
        LoggerMessage.Define<string, Guid, string, int>(
            LogLevel.Warning,
            new EventId(2000, nameof(WebhookEndpointReturnedNonSuccess)),
            "Ashlar security event webhook endpoint returned a non-success response. Endpoint={EndpointName} EventId={EventId} EventType={EventType} StatusCode={StatusCode}");

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AshlarSecurityEventWebhookSender> _logger;
    private readonly IAshlarSecurityEventWebhookDeliveryObserver _observer;
    private readonly AshlarSecurityEventWebhookDestinationValidator _destinationValidator;

    private static readonly Action<ILogger, string, Guid, string, string, Exception?> WebhookEndpointDestinationRejected =
        LoggerMessage.Define<string, Guid, string, string>(
            LogLevel.Warning,
            new EventId(2001, nameof(WebhookEndpointDestinationRejected)),
            "Ashlar security event webhook endpoint destination was rejected. Endpoint={EndpointName} EventId={EventId} EventType={EventType} Reason={Reason}");

    /// <summary>
    /// Initializes a new instance of the webhook sender class.
    /// </summary>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="observer">The delivery observer.</param>
    /// <param name="destinationValidator">The webhook destination safety validator.</param>
    public AshlarSecurityEventWebhookSender(
        IHttpClientFactory httpClientFactory,
        ILogger<AshlarSecurityEventWebhookSender>? logger = null,
        IAshlarSecurityEventWebhookDeliveryObserver? observer = null,
        AshlarSecurityEventWebhookDestinationValidator? destinationValidator = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(destinationValidator);

        _httpClientFactory = httpClientFactory;
        _logger = logger ?? NullLogger<AshlarSecurityEventWebhookSender>.Instance;
        _observer = observer ?? NoOpAshlarSecurityEventWebhookDeliveryObserver.Instance;
        _destinationValidator = destinationValidator;
    }

    /// <inheritdoc />
    public async Task SendAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
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
                return;
            }

            using var request = CreateRequest(delivery);
            var client = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                LogEndpointNonSuccess(delivery, response);
                RecordFailure(delivery, start, AshlarSecurityEventWebhookDeliveryTelemetry.HttpStatusFailureKind);
                return;
            }

            RecordSuccess(delivery, start);
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
