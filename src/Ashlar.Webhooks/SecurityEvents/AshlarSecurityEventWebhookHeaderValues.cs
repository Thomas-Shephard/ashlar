namespace Ashlar.Webhooks.SecurityEvents;

internal static class AshlarSecurityEventWebhookHeaderValues
{
    public static bool IsSafe(string? value)
    {
        return value is not null && value.AsSpan().IndexOfAny('\r', '\n') == -1;
    }

    public static void ThrowIfRequiredUnsafe(string? value, string paramName, string requiredMessage, string unsafeMessage)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(requiredMessage, paramName);
        }

        if (!IsSafe(value))
        {
            throw new ArgumentException(unsafeMessage, paramName);
        }
    }
}
