using System.Text.Json;
using Ashlar.Security.Encryption;

namespace Ashlar.Messaging;

/// <summary>
/// Represents a persisted email outbox entry that is ready for dispatch.
/// </summary>
public sealed class EmailOutboxEntry
{
    /// <summary>
    /// Gets or sets the id value.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Gets or sets the to address value.
    /// </summary>
    public required string ToAddress { get; init; }

    /// <summary>
    /// Gets or sets the from address value.
    /// </summary>
    public string? FromAddress { get; init; }

    /// <summary>
    /// Gets or sets the reply to address value.
    /// </summary>
    public string? ReplyToAddress { get; init; }

    /// <summary>
    /// Gets or sets the CC address value.
    /// </summary>
    public string? CcAddress { get; init; }

    /// <summary>
    /// Gets or sets the BCC address value.
    /// </summary>
    public string? BccAddress { get; init; }

    /// <summary>
    /// Gets or sets the subject value.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Gets or sets the text body value.
    /// </summary>
    public string? TextBody { get; init; }

    /// <summary>
    /// Gets or sets the html body value.
    /// </summary>
    public string? HtmlBody { get; init; }

    /// <summary>
    /// Gets or sets the serialized headers value.
    /// </summary>
    public string? Headers { get; init; }

    /// <summary>
    /// Gets or sets the serialized metadata value.
    /// </summary>
    public string? Metadata { get; init; }

    /// <summary>
    /// Gets or sets the message sensitivity value.
    /// </summary>
    public EmailMessageSensitivity Sensitivity { get; init; } = EmailMessageSensitivity.Normal;

    /// <summary>
    /// Gets or sets the body protection value.
    /// </summary>
    public EmailOutboxBodyProtection BodyProtection { get; init; } = EmailOutboxBodyProtection.None;

    /// <summary>
    /// Gets or sets the attempt count value.
    /// </summary>
    public int AttemptCount { get; init; }
}

/// <summary>
/// Represents a computed outbox delivery failure update.
/// </summary>
/// <param name="AttemptCount">The new attempt count.</param>
/// <param name="FailedAt">The final failure timestamp, if attempts are exhausted.</param>
/// <param name="AvailableAt">The next availability timestamp.</param>
/// <param name="LastError">The truncated error text.</param>
public sealed record EmailOutboxFailureUpdate(
    int AttemptCount,
    DateTimeOffset? FailedAt,
    DateTimeOffset AvailableAt,
    string LastError);

/// <summary>
/// Represents protected body values ready to persist in an email outbox.
/// </summary>
/// <param name="TextBody">The persisted text body.</param>
/// <param name="HtmlBody">The persisted HTML body.</param>
/// <param name="BodyProtection">The body protection marker.</param>
public sealed record EmailOutboxStoredBodies(
    string? TextBody,
    string? HtmlBody,
    EmailOutboxBodyProtection BodyProtection);

/// <summary>
/// Provides callbacks and services for dispatching a durable email outbox entry.
/// </summary>
/// <param name="Transport">The email transport.</param>
/// <param name="MaxAttempts">The maximum configured delivery attempts.</param>
/// <param name="MarkAsSentAsync">The callback that persists successful delivery state.</param>
/// <param name="MarkAsFailedAsync">The callback that persists failed delivery state.</param>
/// <param name="LogDeliveryFailed">The callback that logs failed delivery attempts.</param>
/// <param name="SecretProtector">The optional secret protector used to unprotect protected bodies.</param>
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
    /// <param name="entry">The outbox entry.</param>
    /// <param name="context">The dispatch context.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A task that represents the asynchronous dispatch operation.</returns>
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
    /// <param name="attemptCount">The current attempt count.</param>
    /// <param name="maxAttempts">The configured max attempts.</param>
    /// <param name="initialRetryDelay">The initial retry delay.</param>
    /// <param name="now">The current UTC time.</param>
    /// <param name="exception">The delivery exception.</param>
    /// <param name="suppressErrorDetails">A value indicating whether exception details should be suppressed.</param>
    /// <returns>The computed failure update.</returns>
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
    /// <param name="entry">The outbox entry.</param>
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
    /// <param name="entry">The outbox entry.</param>
    /// <param name="secretProtector">The optional secret protector used to unprotect protected bodies.</param>
    /// <returns>The email message.</returns>
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
    /// <param name="value">The persisted sensitivity value.</param>
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
    /// <param name="message">The email message.</param>
    /// <param name="secretProtector">The optional secret protector.</param>
    /// <returns>The persisted body values and protection marker.</returns>
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
    /// Parses a persisted body protection value.
    /// </summary>
    /// <param name="value">The persisted body protection value.</param>
    /// <returns>The parsed body protection value.</returns>
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
