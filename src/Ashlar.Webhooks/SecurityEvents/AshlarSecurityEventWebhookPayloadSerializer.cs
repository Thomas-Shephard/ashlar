using System.Text.Json;

namespace Ashlar.Webhooks.SecurityEvents;

internal static class AshlarSecurityEventWebhookPayloadSerializer
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static byte[] Serialize(AshlarSecurityEventWebhookPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        return JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
    }
}
