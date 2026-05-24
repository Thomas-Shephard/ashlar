using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Delivers Ashlar security events to configured webhook endpoints on a best-effort basis.
/// </summary>
public sealed class AshlarSecurityEventWebhookHandler : ISecurityEventHandler
{
    /// <summary>
    /// Defines the named HTTP client used by Ashlar security event webhooks.
    /// </summary>
    public const string HttpClientName = "Ashlar.SecurityEventWebhooks";

    internal const string SignatureHeaderName = "X-Ashlar-Signature";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly Action<ILogger, string, Guid, string, int, Exception?> WebhookEndpointReturnedNonSuccess =
        LoggerMessage.Define<string, Guid, string, int>(
            LogLevel.Warning,
            new EventId(2000, nameof(WebhookEndpointReturnedNonSuccess)),
            "Ashlar security event webhook endpoint returned a non-success response. Endpoint={EndpointName} EventId={EventId} EventType={EventType} StatusCode={StatusCode}");

    private static readonly Action<ILogger, string, Guid, string, Exception?> WebhookEndpointFailed =
        LoggerMessage.Define<string, Guid, string>(
            LogLevel.Warning,
            new EventId(2001, nameof(WebhookEndpointFailed)),
            "Ashlar security event webhook endpoint failed. Endpoint={EndpointName} EventId={EventId} EventType={EventType}");

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AshlarSecurityEventWebhookOptions _options;
    private readonly ILogger<AshlarSecurityEventWebhookHandler> _logger;

    /// <summary>
    /// Initializes a new instance of the security event webhook handler class.
    /// </summary>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="options">The webhook options.</param>
    /// <param name="logger">The logger value.</param>
    public AshlarSecurityEventWebhookHandler(
        IHttpClientFactory httpClientFactory,
        IOptions<AshlarSecurityEventWebhookOptions> options,
        ILogger<AshlarSecurityEventWebhookHandler>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(options);

        _httpClientFactory = httpClientFactory;
        _options = options.Value;
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

        var payload = CreatePayload(securityEvent);
        var body = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);

        var tasks = _options.Endpoints
            .Where(endpoint => ShouldSend(endpoint, securityEvent.EventType))
            .Select(endpoint => SendEndpointSafelyAsync(endpoint, securityEvent, body, cancellationToken));

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    internal static AshlarSecurityEventWebhookPayload CreatePayload(AshlarSecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        return new AshlarSecurityEventWebhookPayload
        {
            Id = securityEvent.Id,
            EventType = securityEvent.EventType,
            OccurredAt = securityEvent.OccurredAt,
            Outcome = securityEvent.Outcome,
            FailureReason = securityEvent.FailureReason,
            UserId = securityEvent.UserId,
            TenantId = securityEvent.TenantId,
            ActorUserId = securityEvent.ActorUserId,
            SessionId = securityEvent.SessionId,
            ProviderType = AuthenticationProviderKey.GetTypeValueOrNull(securityEvent.Provider),
            ProviderName = securityEvent.Provider?.Name,
            CorrelationId = securityEvent.CorrelationId
        };
    }

    internal static string CreateSignature(string sharedSecret, ReadOnlySpan<byte> body)
    {
        ArgumentNullException.ThrowIfNull(sharedSecret);

        var secretBytes = Encoding.UTF8.GetBytes(sharedSecret);
        var hash = HMACSHA256.HashData(secretBytes, body);
#if NET9_0_OR_GREATER
        var hex = Convert.ToHexStringLower(hash);
#else
        var hex = Convert.ToHexString(hash).ToLowerInvariant();
#endif
        return string.Concat("sha256=", hex);
    }

    private async Task SendEndpointAsync(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        AshlarSecurityEvent securityEvent,
        byte[] body,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(endpoint, securityEvent, body);
        using var cancellation = CreateCancellationTokenSource(endpoint, cancellationToken);
        var client = _httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.SendAsync(request, cancellation.Token).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            LogEndpointNonSuccess(endpoint, securityEvent, response);
        }
    }

    private async Task SendEndpointSafelyAsync(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        AshlarSecurityEvent securityEvent,
        byte[] body,
        CancellationToken cancellationToken)
    {
        try
        {
            await SendEndpointAsync(endpoint, securityEvent, body, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            LogEndpointFailure(endpoint, securityEvent, exception);
        }
    }

    private static HttpRequestMessage CreateRequest(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        AshlarSecurityEvent securityEvent,
        byte[] body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint.Uri)
        {
            Content = new ByteArrayContent(body)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-Ashlar-Event-Id", securityEvent.Id.ToString("D"));
        request.Headers.Add("X-Ashlar-Event-Type", securityEvent.EventType);
        request.Headers.Add("X-Ashlar-Webhook-Endpoint", endpoint.Name);
        request.Headers.Add("X-Ashlar-Timestamp", securityEvent.OccurredAt.ToString("O"));

        if (!string.IsNullOrEmpty(endpoint.SharedSecret))
        {
            request.Headers.Add(SignatureHeaderName, CreateSignature(endpoint.SharedSecret, body));
        }

        return request;
    }

    private CancellationTokenSource CreateCancellationTokenSource(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        CancellationToken cancellationToken)
    {
        var cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cancellation.CancelAfter(endpoint.Timeout ?? _options.Timeout);
        return cancellation;
    }

    private static bool ShouldSend(AshlarSecurityEventWebhookEndpointOptions endpoint, string eventType)
    {
        return endpoint.Enabled && (endpoint.EventTypes.Count == 0 || endpoint.EventTypes.Contains(eventType));
    }

    private void LogEndpointNonSuccess(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        AshlarSecurityEvent securityEvent,
        HttpResponseMessage response)
    {
        WebhookEndpointReturnedNonSuccess(
            _logger,
            endpoint.Name,
            securityEvent.Id,
            securityEvent.EventType,
            (int)response.StatusCode,
            null);
    }

    private void LogEndpointFailure(
        AshlarSecurityEventWebhookEndpointOptions endpoint,
        AshlarSecurityEvent securityEvent,
        Exception exception)
    {
        WebhookEndpointFailed(_logger, endpoint.Name, securityEvent.Id, securityEvent.EventType, exception);
    }
}
