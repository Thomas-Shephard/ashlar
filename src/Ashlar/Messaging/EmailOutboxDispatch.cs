using System.Text.Json;
using Ashlar.Security.Encryption;

namespace Ashlar.Messaging;

/// <summary>
/// Represents a persisted email outbox entry that is ready for dispatch.
/// </summary>
public sealed class EmailOutboxEntry
{
    /// <summary>
    /// Unique identifier for the outbox entry.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Recipient address. Treat as personal data.
    /// </summary>
    public required string ToAddress { get; init; }

    /// <summary>
    /// Optional sender address.
    /// </summary>
    public string? FromAddress { get; init; }

    /// <summary>
    /// Optional reply-to address.
    /// </summary>
    public string? ReplyToAddress { get; init; }

    /// <summary>
    /// Optional comma-separated CC addresses. Treat as personal data.
    /// </summary>
    public string? CcAddress { get; init; }

    /// <summary>
    /// Optional comma-separated BCC addresses. Treat as personal data.
    /// </summary>
    public string? BccAddress { get; init; }

    /// <summary>
    /// Message subject persisted in the outbox.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Plain-text body, protected according to <see cref="BodyProtection" />.
    /// </summary>
    public string? TextBody { get; init; }

    /// <summary>
    /// HTML body, protected according to <see cref="BodyProtection" />.
    /// </summary>
    public string? HtmlBody { get; init; }

    /// <summary>
    /// Serialized message headers. Do not store credentials or bearer tokens in headers.
    /// </summary>
    public string? Headers { get; init; }

    /// <summary>
    /// Serialized provider-neutral metadata for diagnostics and dispatch. Do not store secrets.
    /// </summary>
    public string? Metadata { get; init; }

    /// <summary>
    /// Sensitivity classification used to decide whether error details and bodies require protection.
    /// </summary>
    public EmailMessageSensitivity Sensitivity { get; init; } = EmailMessageSensitivity.Normal;

    /// <summary>
    /// Protection applied to persisted body columns.
    /// </summary>
    public EmailOutboxBodyProtection BodyProtection { get; init; } = EmailOutboxBodyProtection.None;

    /// <summary>
    /// Number of delivery attempts already made for this entry.
    /// </summary>
    public int AttemptCount { get; init; }
}

/// <summary>
/// Provider-neutral values to persist after an email delivery failure.
/// </summary>
/// <param name="AttemptCount">Delivery attempt count after recording this failure.</param>
/// <param name="FailedAt">UTC time recorded for final failure, if attempts are exhausted.</param>
/// <param name="AvailableAt">UTC time when the outbox row may be retried.</param>
/// <param name="LastError">Truncated diagnostic error text. Sensitive messages use a generic value.</param>
public sealed record EmailOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);

/// <summary>
/// Body column values prepared for email outbox persistence.
/// </summary>
/// <param name="TextBody">Text body value after any required protection.</param>
/// <param name="HtmlBody">HTML body value after any required protection.</param>
/// <param name="BodyProtection">Marker describing how persisted body values are protected.</param>
public sealed record EmailOutboxStoredBodies(
    string? TextBody,
    string? HtmlBody,
    EmailOutboxBodyProtection BodyProtection);

/// <summary>
/// Provider callbacks and <paramref name="Transport" /> dependency used to dispatch one durable outbox entry.
/// </summary>
/// <param name="Transport">The email transport.</param>
/// <param name="MaxAttempts">The maximum configured delivery attempts.</param>
/// <param name="MarkAsSentAsync">Callback that persists successful delivery state.</param>
/// <param name="MarkAsFailedAsync">Callback that persists failed delivery state.</param>
/// <param name="LogDeliveryFailed">Callback that logs failed delivery attempts.</param>
/// <param name="SecretProtector">Optional secret protector used to unprotect protected bodies.</param>
public sealed record EmailOutboxDispatchContext(
    IEmailTransport Transport,
    int MaxAttempts,
    Func<Guid, CancellationToken, Task> MarkAsSentAsync,
    Func<EmailOutboxEntry, Exception, CancellationToken, Task> MarkAsFailedAsync,
    Action<Guid, int, bool, Exception?> LogDeliveryFailed,
    ISecretProtector? SecretProtector = null);

/// <summary>
/// Defines the protection applied to persisted email outbox body columns.
/// </summary>
public enum EmailOutboxBodyProtection
{
    /// <summary>
    /// The body protection value is unknown or invalid.
    /// </summary>
    Unknown = -1,

    /// <summary>
    /// No body protection is applied.
    /// </summary>
    None,

    /// <summary>
    /// Body values are protected with Ashlar's <see cref="ISecretProtector"/>.
    /// </summary>
    SecretProtector
}

/// <summary>
/// Shared email outbox dispatch behavior for persistence providers.
/// </summary>
public static class EmailOutboxDispatch
{
    private const int MaxLastErrorLength = 1000;
    private const string SafeLastError = "Email outbox delivery failed. Error details were suppressed because the message may contain sensitive content.";
    private const string MissingSecretProtectorMessage = "Email outbox body protection requires an ISecretProtector.";

    /// <summary>
    /// Sends a durable outbox entry and applies the provided success or failure persistence callbacks.
    /// </summary>
    /// <param name="entry">The outbox entry to send and mutate through callbacks.</param>
    /// <param name="context">Transport and persistence callbacks supplied by the provider.</param>
    /// <param name="cancellationToken">A token that can cancel delivery before provider callbacks are invoked.</param>
    /// <returns>A task that completes after delivery succeeds or the failure callbacks have persisted the failure state.</returns>
    public static async Task DispatchAsync(
        EmailOutboxEntry entry,
        EmailOutboxDispatchContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.Transport);
        ArgumentNullException.ThrowIfNull(context.MarkAsSentAsync);
        ArgumentNullException.ThrowIfNull(context.MarkAsFailedAsync);
        ArgumentNullException.ThrowIfNull(context.LogDeliveryFailed);

        try
        {
            var message = MapToEmailMessage(entry, context.SecretProtector);
            await context.Transport.DeliverAsync(message, cancellationToken).ConfigureAwait(false);
            await context.MarkAsSentAsync(entry.Id, CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            await MarkAsFailedAsync(entry, context, exception).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Computes the provider-specific values used to mark a failed delivery attempt.
    /// </summary>
    /// <param name="attemptCount">Delivery attempt count before recording this failure.</param>
    /// <param name="maxAttempts">Configured delivery attempt limit.</param>
    /// <param name="initialRetryDelay">Base delay used to calculate exponential retry backoff.</param>
    /// <param name="now">UTC time used to decide the next retry or final failure timestamp.</param>
    /// <param name="exception">Delivery exception from the transport.</param>
    /// <param name="suppressErrorDetails">Whether exception details should be suppressed because the message may contain secrets.</param>
    /// <returns>Failure update to persist for the outbox row.</returns>
    public static EmailOutboxFailureUpdate CreateFailureUpdate(
        int attemptCount,
        int maxAttempts,
        TimeSpan initialRetryDelay,
        DateTimeOffset now,
        Exception exception,
        bool suppressErrorDetails = false)
    {
        ArgumentNullException.ThrowIfNull(exception);

        var nextAttemptCount = attemptCount + 1;
        var isFinalFailure = nextAttemptCount >= maxAttempts;
        var backoffMultiplier = Math.Pow(2, nextAttemptCount - 1);
        var maxDelayTicks = TimeSpan.FromDays(7).Ticks;
        var delayTicks = Math.Min(initialRetryDelay.Ticks * backoffMultiplier, maxDelayTicks);
        var availableAt = isFinalFailure ? now : now.AddTicks((long)delayTicks);
        var lastError = suppressErrorDetails ? SafeLastError : exception.ToString();
        if (lastError.Length > MaxLastErrorLength)
        {
            lastError = lastError[..MaxLastErrorLength];
        }

        return new EmailOutboxFailureUpdate(
            nextAttemptCount,
            isFinalFailure ? now : null,
            availableAt,
            lastError);
    }

    /// <summary>
    /// Determines whether failure details should be suppressed for a persisted email outbox entry.
    /// </summary>
    /// <param name="entry">Persisted outbox entry whose sensitivity and body protection are inspected.</param>
    /// <returns><see langword="true"/> when failure details may contain sensitive content.</returns>
    public static bool ShouldSuppressFailureDetails(EmailOutboxEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return entry.Sensitivity == EmailMessageSensitivity.ContainsLiveSecret ||
            entry.BodyProtection != EmailOutboxBodyProtection.None;
    }

    /// <summary>
    /// Maps a persisted outbox entry to an email message.
    /// </summary>
    /// <param name="entry">Persisted outbox entry to map for delivery.</param>
    /// <param name="secretProtector">Optional secret protector used to unprotect protected bodies.</param>
    /// <returns>Email message ready for transport delivery.</returns>
    public static EmailMessage MapToEmailMessage(EmailOutboxEntry entry, ISecretProtector? secretProtector = null)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var headers = entry.Headers != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Headers) : null;
        var metadata = entry.Metadata != null ? JsonSerializer.Deserialize<Dictionary<string, string>>(entry.Metadata) : null;
        ValidateBodyProtection(entry);
        var textBody = UnprotectBody(entry.TextBody, entry.BodyProtection, secretProtector);
        var htmlBody = UnprotectBody(entry.HtmlBody, entry.BodyProtection, secretProtector);

        return new EmailMessage(
            entry.ToAddress,
            entry.Subject,
            textBody,
            htmlBody,
            new EmailMessageOptions
            {
                From = entry.FromAddress,
                ReplyTo = entry.ReplyToAddress,
                Cc = entry.CcAddress,
                Bcc = entry.BccAddress,
                Headers = headers,
                Metadata = metadata,
                Sensitivity = entry.Sensitivity
            });
    }

    /// <summary>
    /// Parses a persisted sensitivity value into a safe message sensitivity.
    /// </summary>
    /// <param name="value">Persisted sensitivity marker from the outbox row.</param>
    /// <returns>The parsed sensitivity, or <see cref="EmailMessageSensitivity.Normal"/> for unknown values.</returns>
    public static EmailMessageSensitivity ParseSensitivity(string? value)
    {
        if (value != null && value.Equals(nameof(EmailMessageSensitivity.ContainsLiveSecret), StringComparison.OrdinalIgnoreCase))
        {
            return EmailMessageSensitivity.ContainsLiveSecret;
        }

        return EmailMessageSensitivity.Normal;
    }

    /// <summary>
    /// Protects body values before an email outbox row is persisted.
    /// </summary>
    /// <param name="message">Email message whose bodies will be persisted.</param>
    /// <param name="secretProtector">Optional secret protector required for messages containing live secrets.</param>
    /// <returns>Body values and protection marker to store in the outbox row.</returns>
    public static EmailOutboxStoredBodies ProtectBodiesForStorage(EmailMessage message, ISecretProtector? secretProtector = null)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (message.Sensitivity != EmailMessageSensitivity.ContainsLiveSecret)
        {
            return new EmailOutboxStoredBodies(message.TextBody, message.HtmlBody, EmailOutboxBodyProtection.None);
        }

        if (secretProtector == null)
        {
            throw new InvalidOperationException(MissingSecretProtectorMessage);
        }

        return new EmailOutboxStoredBodies(
            ProtectBody(message.TextBody, secretProtector),
            ProtectBody(message.HtmlBody, secretProtector),
            EmailOutboxBodyProtection.SecretProtector);
    }

    /// <summary>
    /// Parses a persisted body protection marker.
    /// </summary>
    /// <param name="value">Persisted body protection marker from the outbox row.</param>
    /// <returns>Parsed body protection marker.</returns>
    public static EmailOutboxBodyProtection ParseBodyProtection(string? value)
    {
        if (value != null && value.Equals(nameof(EmailOutboxBodyProtection.None), StringComparison.OrdinalIgnoreCase))
        {
            return EmailOutboxBodyProtection.None;
        }

        if (value != null && value.Equals(nameof(EmailOutboxBodyProtection.SecretProtector), StringComparison.OrdinalIgnoreCase))
        {
            return EmailOutboxBodyProtection.SecretProtector;
        }

        return EmailOutboxBodyProtection.Unknown;
    }

    private static string? ProtectBody(string? body, ISecretProtector secretProtector)
    {
        return body == null ? null : secretProtector.Protect(body);
    }

    private static async Task MarkAsFailedAsync(
        EmailOutboxEntry entry,
        EmailOutboxDispatchContext context,
        Exception exception)
    {
        var attemptCount = entry.AttemptCount + 1;
        var suppressFailureDetails = ShouldSuppressFailureDetails(entry);
        context.LogDeliveryFailed(entry.Id, attemptCount, attemptCount >= context.MaxAttempts, suppressFailureDetails ? null : exception);
        await context.MarkAsFailedAsync(entry, exception, CancellationToken.None).ConfigureAwait(false);
    }

    private static void ValidateBodyProtection(EmailOutboxEntry entry)
    {
        if (entry.Sensitivity == EmailMessageSensitivity.ContainsLiveSecret &&
            entry.BodyProtection != EmailOutboxBodyProtection.SecretProtector)
        {
            throw new InvalidOperationException("Email outbox row contains live secrets without protected bodies.");
        }
    }

    private static string? UnprotectBody(string? body, EmailOutboxBodyProtection bodyProtection, ISecretProtector? secretProtector)
    {
        return bodyProtection switch
        {
            EmailOutboxBodyProtection.None => body,
            EmailOutboxBodyProtection.SecretProtector => body == null ? null : UnprotectRequiredBody(body, secretProtector),
            _ => throw new InvalidOperationException("Email outbox row has an unknown body protection value.")
        };
    }

    private static string UnprotectRequiredBody(string body, ISecretProtector? secretProtector)
    {
        if (secretProtector == null)
        {
            throw new InvalidOperationException(MissingSecretProtectorMessage);
        }

        return secretProtector.Unprotect(body);
    }
}
