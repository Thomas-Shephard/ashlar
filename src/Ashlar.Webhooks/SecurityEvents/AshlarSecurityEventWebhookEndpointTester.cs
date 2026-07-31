using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Features.Administration;
using Ashlar.Identity.Models.AccountSecurity;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Tests configured Ashlar security event webhook endpoints with a synthetic signed request.
/// </summary>
public interface IAshlarSecurityEventWebhookEndpointTester
{
    /// <summary>
    /// Sends one synthetic test webhook request to the configured endpoint named by <paramref name="endpointName" />.
    /// </summary>
    /// <param name="actor">The authenticated and proof-bound actor.</param>
    /// <param name="endpointName">The configured endpoint name.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The safe test result.</returns>
    Task<AshlarSecurityEventWebhookEndpointTestResult> TestAsync(
        AccountSecurityActorContext actor,
        string endpointName,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Defines endpoint test delivery statuses.
/// </summary>
public enum AshlarSecurityEventWebhookEndpointTestStatus
{
    /// <summary>
    /// The synthetic webhook request was sent and the endpoint returned a success response.
    /// </summary>
    Sent = 0,

    /// <summary>
    /// No configured endpoint matched the requested name.
    /// </summary>
    EndpointNotFound = 1,

    /// <summary>
    /// The configured endpoint is disabled.
    /// </summary>
    EndpointDisabled = 2,

    /// <summary>
    /// The configured destination was rejected by destination validation.
    /// </summary>
    DestinationRejected = 3,

    /// <summary>
    /// The endpoint requires a valid shared secret but its signing configuration is invalid.
    /// </summary>
    InvalidSharedSecret = 4,

    /// <summary>
    /// The endpoint returned a non-success response or delivery failed.
    /// </summary>
    DeliveryFailed = 5,

    /// <summary>
    /// The endpoint test timed out.
    /// </summary>
    TimedOut = 6,

    /// <summary>
    /// The endpoint test was canceled by the caller.
    /// </summary>
    Canceled = 7,

    /// <summary>
    /// The actor was not authorized to test webhook endpoints.
    /// </summary>
    Unauthorized = 8
}

/// <summary>
/// Represents the safe result of testing a configured security event webhook endpoint.
/// </summary>
/// <param name="Status">The explicit endpoint test status.</param>
/// <param name="EventId">The synthetic event identifier when a request was prepared.</param>
public sealed record AshlarSecurityEventWebhookEndpointTestResult(
    AshlarSecurityEventWebhookEndpointTestStatus Status,
    Guid? EventId = null)
{
    /// <summary>
    /// Gets a value indicating whether the test request was sent successfully.
    /// </summary>
    public bool Succeeded => Status == AshlarSecurityEventWebhookEndpointTestStatus.Sent;

    /// <summary>
    /// Gets a safe failure reason suitable for logs and public diagnostics.
    /// </summary>
    public string FailureReason => Status switch
    {
        AshlarSecurityEventWebhookEndpointTestStatus.Sent => string.Empty,
        AshlarSecurityEventWebhookEndpointTestStatus.EndpointNotFound => "Webhook endpoint was not found.",
        AshlarSecurityEventWebhookEndpointTestStatus.EndpointDisabled => "Webhook endpoint is disabled.",
        AshlarSecurityEventWebhookEndpointTestStatus.DestinationRejected => "Webhook destination was rejected.",
        AshlarSecurityEventWebhookEndpointTestStatus.InvalidSharedSecret => "Webhook endpoint has no valid shared secret.",
        AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed => "Webhook endpoint delivery failed.",
        AshlarSecurityEventWebhookEndpointTestStatus.TimedOut => "Webhook endpoint test timed out.",
        AshlarSecurityEventWebhookEndpointTestStatus.Canceled => "Webhook endpoint test was canceled.",
        AshlarSecurityEventWebhookEndpointTestStatus.Unauthorized => "Webhook endpoint test was not authorized.",
        _ => "Webhook endpoint delivery failed."
    };
}

/// <summary>
/// Tests configured Ashlar security event webhook endpoints with a synthetic signed request.
/// </summary>
public sealed class AshlarSecurityEventWebhookEndpointTester : IAshlarSecurityEventWebhookEndpointTester
{
    /// <summary>
    /// Defines the synthetic security event webhook test event type.
    /// </summary>
    public const string TestEventType = "ashlar.webhook.test";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly AshlarSecurityEventWebhookOptions _options;
    private readonly IAshlarSecurityEventWebhookSender _sender;
    private readonly TimeProvider _timeProvider;
    private readonly AccountSecurityOperationBoundary _boundary;

    /// <summary>
    /// Initializes a new instance of the endpoint tester class.
    /// </summary>
    /// <param name="options">The webhook options.</param>
    /// <param name="sender">The shared webhook sender.</param>
    /// <param name="sessions">The authentication-session repository.</param>
    /// <param name="authorizer">The host operation authorizer.</param>
    /// <param name="auditSink">The durable audit sink.</param>
    /// <param name="timeProvider">The time provider.</param>
    public AshlarSecurityEventWebhookEndpointTester(
        IOptions<AshlarSecurityEventWebhookOptions> options,
        IAshlarSecurityEventWebhookSender sender,
        IAuthenticationSessionRepository sessions,
        IAccountSecurityOperationAuthorizer authorizer,
        IPersistentSecurityEventSink auditSink,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(sender);

        _options = options.Value;
        _sender = sender;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _boundary = new AccountSecurityOperationBoundary(sessions, authorizer, auditSink, _timeProvider,
            IAccountSecurityAdministrationService.ProofPurpose, "security_event_webhook.endpoint_test");
    }

    /// <inheritdoc />
    public async Task<AshlarSecurityEventWebhookEndpointTestResult> TestAsync(
        AccountSecurityActorContext actor,
        string endpointName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointName);
        cancellationToken.ThrowIfCancellationRequested();
        if (await _boundary.AuthorizeAsync(actor, null, true, Guid.Empty,
                AccountSecurityOperation.TestSecurityEventWebhookEndpoint, cancellationToken).ConfigureAwait(false) is not null)
        {
            return new AshlarSecurityEventWebhookEndpointTestResult(AshlarSecurityEventWebhookEndpointTestStatus.Unauthorized);
        }

        var endpoint = _options.Endpoints.FirstOrDefault(endpoint =>
            string.Equals(endpoint.Name, endpointName, StringComparison.Ordinal));
        if (endpoint is null)
        {
            return await CompleteAsync(actor, new AshlarSecurityEventWebhookEndpointTestResult(
                AshlarSecurityEventWebhookEndpointTestStatus.EndpointNotFound)).ConfigureAwait(false);
        }

        if (!endpoint.Enabled)
        {
            return await CompleteAsync(actor, new AshlarSecurityEventWebhookEndpointTestResult(
                AshlarSecurityEventWebhookEndpointTestStatus.EndpointDisabled)).ConfigureAwait(false);
        }

        if (!AshlarSecurityEventWebhookSignature.IsSigningConfigurationValid(
                endpoint.SharedSecret,
                endpoint.AllowUnsigned))
        {
            return await CompleteAsync(actor, new AshlarSecurityEventWebhookEndpointTestResult(
                AshlarSecurityEventWebhookEndpointTestStatus.InvalidSharedSecret)).ConfigureAwait(false);
        }

        AshlarSecurityEventWebhookPayload? payload = null;

        try
        {
            payload = CreatePayload();
            var body = JsonSerializer.SerializeToUtf8Bytes(
                new SyntheticSecurityEventWebhookTestPayload(payload.Id, payload.EventType, payload.OccurredAt),
                JsonOptions);
            var delivery = new AshlarSecurityEventWebhookDelivery(
                endpoint.Name,
                endpoint.Uri ?? throw new InvalidOperationException("Active webhook endpoint is missing a URI."),
                endpoint.Timeout ?? _options.Timeout,
                AshlarSecurityEventWebhookDeliveryFactory.CreateHeaders(endpoint, payload, body, _timeProvider.GetUtcNow()),
                payload,
                body);
            var result = await _sender.SendAsync(delivery, cancellationToken).ConfigureAwait(false);
            return await CompleteAsync(actor, new AshlarSecurityEventWebhookEndpointTestResult(MapStatus(result), payload.Id)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return await CompleteAsync(actor, new AshlarSecurityEventWebhookEndpointTestResult(
                cancellationToken.IsCancellationRequested
                    ? AshlarSecurityEventWebhookEndpointTestStatus.Canceled
                    : AshlarSecurityEventWebhookEndpointTestStatus.TimedOut,
                payload?.Id)).ConfigureAwait(false);
        }
        catch
        {
            return await CompleteAsync(actor, new AshlarSecurityEventWebhookEndpointTestResult(
                AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed,
                payload?.Id)).ConfigureAwait(false);
        }
    }

    private async Task<AshlarSecurityEventWebhookEndpointTestResult> CompleteAsync(
        AccountSecurityActorContext actor,
        AshlarSecurityEventWebhookEndpointTestResult result)
    {
        if (result.Succeeded)
            await _boundary.RecordSuccessAsync(actor, null, true, AccountSecurityOperation.TestSecurityEventWebhookEndpoint).ConfigureAwait(false);
        else
            await _boundary.RecordFailureAsync(actor, null, true, AccountSecurityOperation.TestSecurityEventWebhookEndpoint).ConfigureAwait(false);
        return result;
    }

    private AshlarSecurityEventWebhookPayload CreatePayload()
    {
        return new AshlarSecurityEventWebhookPayload
        {
            Id = Guid.NewGuid(),
            EventType = TestEventType,
            OccurredAt = _timeProvider.GetUtcNow(),
            Outcome = SecurityEventOutcomes.Success
        };
    }

    internal static AshlarSecurityEventWebhookEndpointTestStatus MapStatus(AshlarSecurityEventWebhookSendResult result)
    {
        return result switch
        {
            AshlarSecurityEventWebhookSendResult.Sent => AshlarSecurityEventWebhookEndpointTestStatus.Sent,
            AshlarSecurityEventWebhookSendResult.DestinationRejected => AshlarSecurityEventWebhookEndpointTestStatus.DestinationRejected,
            AshlarSecurityEventWebhookSendResult.DeliveryFailed => AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed,
            _ => AshlarSecurityEventWebhookEndpointTestStatus.DeliveryFailed
        };
    }

    private sealed record SyntheticSecurityEventWebhookTestPayload(
        Guid Id,
        string EventType,
        DateTimeOffset OccurredAt);
}
