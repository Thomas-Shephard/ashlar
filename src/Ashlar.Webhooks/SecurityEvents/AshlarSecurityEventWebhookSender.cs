using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
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

    internal const string SignatureHeaderName = "X-Ashlar-Signature";

    private static readonly Action<ILogger, string, Guid, string, int, Exception?> WebhookEndpointReturnedNonSuccess =
        LoggerMessage.Define<string, Guid, string, int>(
            LogLevel.Warning,
            new EventId(2000, nameof(WebhookEndpointReturnedNonSuccess)),
            "Ashlar security event webhook endpoint returned a non-success response. Endpoint={EndpointName} EventId={EventId} EventType={EventType} StatusCode={StatusCode}");

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AshlarSecurityEventWebhookSender> _logger;

    /// <summary>
    /// Initializes a new instance of the webhook sender class.
    /// </summary>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    /// <param name="logger">The logger value.</param>
    public AshlarSecurityEventWebhookSender(
        IHttpClientFactory httpClientFactory,
        ILogger<AshlarSecurityEventWebhookSender>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);

        _httpClientFactory = httpClientFactory;
        _logger = logger ?? NullLogger<AshlarSecurityEventWebhookSender>.Instance;
    }

    /// <inheritdoc />
    public async Task SendAsync(AshlarSecurityEventWebhookDelivery delivery, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(delivery);

        using var request = CreateRequest(delivery);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(delivery.Timeout);

        var client = _httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.SendAsync(request, timeout.Token).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            LogEndpointNonSuccess(delivery, response);
        }
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
}
