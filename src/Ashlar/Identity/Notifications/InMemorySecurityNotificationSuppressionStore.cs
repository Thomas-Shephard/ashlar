using System.Collections.Concurrent;

namespace Ashlar.Identity.Notifications;

/// <summary>
/// Provides in memory security notification suppression store behavior.
/// </summary>
public sealed class InMemorySecurityNotificationSuppressionStore : ISecurityNotificationSuppressionStore
{
    private const int CleanupInterval = 256;
    private static readonly object[] KeyLocks = Enumerable.Range(0, 64).Select(_ => new object()).ToArray();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _suppressedUntil = new(StringComparer.Ordinal);
    private int _attemptsSinceCleanup;

    /// <summary>
    /// Performs the should send operation and returns the result.
    /// </summary>
    /// <param name="notification">The notification value.</param>
    /// <param name="cooldown">The cooldown value.</param>
    /// <param name="now">The now value.</param>
    /// <returns>The operation result.</returns>
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
        lock (GetKeyLock(key))
        {
            if (_suppressedUntil.TryGetValue(key, out var existingSuppressedUntil)
                && now < existingSuppressedUntil)
            {
                return false;
            }

            _suppressedUntil[key] = suppressedUntil;
            return true;
        }
    }

    private static object GetKeyLock(string key)
    {
        return KeyLocks[StringComparer.Ordinal.GetHashCode(key) & (KeyLocks.Length - 1)];
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
