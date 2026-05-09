using System.Collections.Concurrent;

namespace Ashlar.Identity.Notifications;

public sealed class InMemorySecurityNotificationSuppressionStore : ISecurityNotificationSuppressionStore
{
    private const int CleanupInterval = 256;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _suppressedUntil = new(StringComparer.Ordinal);
    private int _attemptsSinceCleanup;

    public bool ShouldSend(SecurityNotification notification, TimeSpan cooldown, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(notification);
        if (cooldown <= TimeSpan.Zero)
        {
            return true;
        }

        TryCleanupExpiredEntries(now);
        var key = CreateKey(notification);
        var suppressedUntil = now + cooldown;
        while (true)
        {
            if (!_suppressedUntil.TryGetValue(key, out var existingSuppressedUntil))
            {
                if (_suppressedUntil.TryAdd(key, suppressedUntil))
                {
                    return true;
                }

                continue;
            }

            if (now < existingSuppressedUntil)
            {
                return false;
            }

            if (_suppressedUntil.TryUpdate(key, suppressedUntil, existingSuppressedUntil))
            {
                return true;
            }
        }
    }

    private static string CreateKey(SecurityNotification notification)
    {
        return string.Concat(
            IdentityNormalization.NormalizeEmail(notification.RecipientEmail),
            "|",
            notification.Type.ToString());
    }

    private void TryCleanupExpiredEntries(DateTimeOffset now)
    {
        var attempts = Interlocked.Increment(ref _attemptsSinceCleanup);
        if (attempts % CleanupInterval != 0)
        {
            return;
        }

        foreach (var entry in _suppressedUntil)
        {
            if (now >= entry.Value)
            {
                _suppressedUntil.TryRemove(entry);
            }
        }
    }
}
