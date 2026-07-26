namespace Ashlar.Webhooks.SecurityEvents;

/// <summary>
/// Sends webhook requests through Ashlar's SSRF-hardened transport.
/// Custom outbox providers must resolve this service rather than supply an HTTP client or handler.
/// </summary>
public sealed class AshlarSecurityEventWebhookTransport : IDisposable
{
    private readonly HttpClient _httpClient;

    internal AshlarSecurityEventWebhookTransport(
        AshlarSecurityEventWebhookDestinationValidator destinationValidator,
        IEnumerable<Action<HttpClient>> configureHttpClient)
        : this(CreatePrimaryHandler(destinationValidator))
    {
        foreach (var configure in configureHttpClient)
        {
            configure(_httpClient);
        }
    }

    internal AshlarSecurityEventWebhookTransport(HttpMessageHandler primaryHandler)
    {
        _httpClient = new HttpClient(primaryHandler ?? throw new ArgumentNullException(nameof(primaryHandler)), disposeHandler: true);
    }

    private static HttpMessageHandler CreatePrimaryHandler(AshlarSecurityEventWebhookDestinationValidator destinationValidator)
    {
        ArgumentNullException.ThrowIfNull(destinationValidator);
        return AshlarSecurityEventWebhookHttpMessageHandlerFactory.Create(destinationValidator);
    }

    internal Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
    }

    /// <summary>
    /// Disposes the owned HTTP client and hardened handler.
    /// </summary>
    public void Dispose()
    {
        _httpClient.Dispose();
    }
}

internal sealed class AshlarSecurityEventWebhookTransportOptions
{
    public List<Action<HttpClient>> Configurations { get; } = [];
}
