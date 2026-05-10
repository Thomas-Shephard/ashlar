using System.Text.RegularExpressions;
using Ashlar.Messaging;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Notifications;

public sealed partial class SecurityNotificationService(
    IEmailSender emailSender,
    IOptions<SecurityNotificationOptions> options,
    ISecurityNotificationSuppressionStore? suppressionStore = null,
    TimeProvider? timeProvider = null)
    : ISecurityNotificationService
{
    private readonly IEmailSender _emailSender = emailSender ?? throw new ArgumentNullException(nameof(emailSender));
    private readonly IOptions<SecurityNotificationOptions> _options = options ?? throw new ArgumentNullException(nameof(options));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<SecurityNotificationResult> NotifyAsync(
        SecurityNotification notification,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(notification);

        var opt = _options.Value;
        if (!opt.Enabled || !opt.EnabledTypes.Contains(notification.Type))
        {
            return SecurityNotificationResult.Success();
        }

        if (!opt.TemplateOverrides.TryGetValue(notification.Type, out var template)
            && !SecurityNotificationOptions.DefaultTemplates.TryGetValue(notification.Type, out template))
        {
            return SecurityNotificationResult.Failure($"No template found for notification type {notification.Type}");
        }

        if (opt.Cooldowns.TryGetValue(notification.Type, out var cooldown)
            && cooldown > TimeSpan.Zero
            && suppressionStore != null
            && !suppressionStore.ShouldSend(notification, cooldown, _timeProvider.GetUtcNow()))
        {
            return SecurityNotificationResult.SuppressedResult();
        }

        var recipientEmail = IdentityNormalization.SanitizeEmailForDelivery(notification.RecipientEmail);
        var subject = Render(template.Subject, notification, opt);
        var body = Render(template.Body, notification, opt);

        try
        {
            await _emailSender.SendAsync(new EmailMessage(
                recipientEmail,
                subject,
                body,
                options: new EmailMessageOptions { From = opt.FromAddress }), cancellationToken);
        }
        catch (Exception ex)
        {
            return SecurityNotificationResult.Failure(ex.Message);
        }

        return SecurityNotificationResult.Success();
    }

    private static string Render(string text, SecurityNotification notification, SecurityNotificationOptions options)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["RecipientEmail"] = notification.RecipientEmail,
            ["OccurredAt"] = notification.OccurredAt.ToString("f", System.Globalization.CultureInfo.InvariantCulture),
            ["Type"] = notification.Type.ToString(),
            ["IpAddress"] = options.IncludeIpAddress ? notification.IpAddress ?? "unknown" : "[redacted]",
            ["UserAgent"] = options.IncludeUserAgent ? notification.UserAgent ?? "unknown" : "[redacted]",
            ["SessionId"] = notification.SessionId?.ToString() ?? string.Empty
        };

        if (notification.Metadata != null)
        {
            foreach (var kvp in notification.Metadata.Where(kvp => !string.IsNullOrWhiteSpace(kvp.Key) && !values.ContainsKey(kvp.Key)))
            {
                values[kvp.Key] = NormalizePlaceholderValue(kvp.Value);
            }
        }

        return TemplatePlaceholderRegex().Replace(text, match =>
            {
                var key = match.Groups["key"].Value;
                return values.TryGetValue(key, out var value) ? EncodeValue(value) : match.Value;
            });
    }

    private static string EncodeValue(string? value)
    {
        var normalized = NormalizePlaceholderValue(value);
        return normalized.Replace("\r", string.Empty).Replace("\n", " ");
    }

    private static string NormalizePlaceholderValue(string? value) => value ?? string.Empty;

    [GeneratedRegex(@"\{(?<key>[^}]+)\}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TemplatePlaceholderRegex();
}
