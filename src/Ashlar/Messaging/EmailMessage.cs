using System.Collections.ObjectModel;

namespace Ashlar.Messaging;

/// <summary>
/// Framework-neutral email envelope produced by Ashlar flows.
/// </summary>
public sealed record EmailMessage
{
    /// <summary>
    /// Creates an email message.
    /// </summary>
    /// <param name="to">Recipient address after header-injection validation.</param>
    /// <param name="subject">Message subject after header-injection validation.</param>
    /// <param name="sensitivity">Explicit classification of whether the body contains live secret material.</param>
    /// <param name="textBody">Plain-text body, required when no HTML body is supplied.</param>
    /// <param name="htmlBody">HTML body, required when no plain-text body is supplied.</param>
    /// <param name="options">Optional sender, routing, headers, and metadata.</param>
    public EmailMessage(
        string to,
        string subject,
        EmailMessageSensitivity sensitivity,
        string? textBody = null,
        string? htmlBody = null,
        EmailMessageOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(to))
        {
            throw new ArgumentException("The recipient address is required.", nameof(to));
        }

        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentException("The email subject is required.", nameof(subject));
        }

        if (string.IsNullOrWhiteSpace(textBody) && string.IsNullOrWhiteSpace(htmlBody))
        {
            throw new ArgumentException("An email message must include a text or HTML body.", nameof(textBody));
        }

        if (sensitivity is not EmailMessageSensitivity.Normal and not EmailMessageSensitivity.ContainsLiveSecret)
        {
            throw new ArgumentOutOfRangeException(nameof(sensitivity));
        }

        ValidateHeader("To", to);
        ValidateHeader("Subject", subject);

        To = to;
        Subject = subject;
        TextBody = textBody;
        HtmlBody = htmlBody;
        From = options?.From;
        ReplyTo = options?.ReplyTo;
        Cc = options?.Cc;
        Bcc = options?.Bcc;
        Sensitivity = sensitivity;

        if (From != null)
        {
            ValidateHeader("From", From);
        }

        if (ReplyTo != null)
        {
            ValidateHeader("ReplyTo", ReplyTo);
        }

        if (Cc != null)
        {
            ValidateHeader("Cc", Cc);
        }

        if (Bcc != null)
        {
            ValidateHeader("Bcc", Bcc);
        }

        if (options?.Headers != null)
        {
            foreach (var header in options.Headers)
            {
                ValidateHeader(header.Key, header.Value);
            }
            Headers = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(options.Headers));
        }

        Metadata = options?.Metadata is null ? null : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(options.Metadata));
    }

    private static void ValidateHeader(string name, string value)
    {
        if (HasInjectionCharacters(name))
        {
            throw new ArgumentException($"Invalid header name: '{name}'.", nameof(name));
        }

        if (HasInjectionCharacters(value))
        {
            throw new ArgumentException($"Invalid header value for '{name}'.", name is "To" or "Subject" ? name.ToLowerInvariant() : "options");
        }
    }

    private static bool HasInjectionCharacters(string? value)
    {
        return value?.Any(c => c is '\r' or '\n' or '\0') ?? false;
    }

    /// <summary>
    /// Recipient address after header-injection validation.
    /// </summary>
    public string To { get; }

    /// <summary>
    /// Message subject after header-injection validation.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Plain-text body, required when no HTML body is supplied.
    /// </summary>
    public string? TextBody { get; }

    /// <summary>
    /// HTML body, required when no plain-text body is supplied.
    /// </summary>
    public string? HtmlBody { get; }

    /// <summary>
    /// Optional sender address after header-injection validation.
    /// </summary>
    public string? From { get; }

    /// <summary>
    /// Optional reply-to address after header-injection validation.
    /// </summary>
    public string? ReplyTo { get; }

    /// <summary>
    /// Optional CC recipients after header-injection validation.
    /// </summary>
    public string? Cc { get; }

    /// <summary>
    /// Optional BCC recipients after header-injection validation.
    /// </summary>
    public string? Bcc { get; }

    /// <summary>
    /// Additional message headers. Do not include credentials or bearer tokens.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; }

    /// <summary>
    /// Provider-neutral metadata for transports and diagnostics. Do not include secrets.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; }

    /// <summary>
    /// Explicit classification of whether the body contains live secret material such as tokens, links, or codes.
    /// </summary>
    public EmailMessageSensitivity Sensitivity { get; }
}

/// <summary>
/// Classifies whether an Ashlar email message contains live secret material.
/// </summary>
/// <remarks>
/// Names are persisted by durable outbox providers and should not be renamed without a data migration.
/// </remarks>
public enum EmailMessageSensitivity
{
    /// <summary>
    /// The message does not contain a live secret.
    /// </summary>
    Normal = 1,

    /// <summary>
    /// The message contains a currently valid secret such as a token, link, or code.
    /// </summary>
    ContainsLiveSecret = 2
}

/// <summary>
/// Optional email envelope data for framework-neutral Ashlar messages.
/// </summary>
public sealed record EmailMessageOptions
{
    /// <summary>
    /// Optional sender address after header-injection validation.
    /// </summary>
    public string? From { get; init; }

    /// <summary>
    /// Optional reply-to address after header-injection validation.
    /// </summary>
    public string? ReplyTo { get; init; }

    /// <summary>
    /// Optional CC recipients after header-injection validation.
    /// </summary>
    public string? Cc { get; init; }

    /// <summary>
    /// Optional BCC recipients after header-injection validation.
    /// </summary>
    public string? Bcc { get; init; }

    /// <summary>
    /// Additional message headers. Do not include credentials or bearer tokens.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    /// <summary>
    /// Provider-neutral metadata for transports and diagnostics. Do not include secrets.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
