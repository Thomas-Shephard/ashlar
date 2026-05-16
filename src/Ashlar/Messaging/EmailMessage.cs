using System.Collections.ObjectModel;

namespace Ashlar.Messaging;

/// <summary>
/// Represents an email message produced by framework-neutral Ashlar flows.
/// </summary>
public sealed record EmailMessage
{
    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="to">The to value.</param>
    /// <param name="subject">The subject value.</param>
    /// <param name="textBody">The text body value.</param>
    /// <param name="htmlBody">The html body value.</param>
    /// <param name="options">The options value.</param>
    public EmailMessage(
        string to,
        string subject,
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
    /// Gets or sets the to value.
    /// </summary>
    public string To { get; }

    /// <summary>
    /// Gets or sets the subject value.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets or sets the text body value.
    /// </summary>
    public string? TextBody { get; }

    /// <summary>
    /// Gets or sets the html body value.
    /// </summary>
    public string? HtmlBody { get; }

    /// <summary>
    /// Gets or sets the from value.
    /// </summary>
    public string? From { get; }

    /// <summary>
    /// Gets or sets the reply to value.
    /// </summary>
    public string? ReplyTo { get; }

    /// <summary>
    /// Gets or sets the cc value.
    /// </summary>
    public string? Cc { get; }

    /// <summary>
    /// Gets or sets the bcc value.
    /// </summary>
    public string? Bcc { get; }

    /// <summary>
    /// Gets or sets the headers value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; }

    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; }
}

/// <summary>
/// Optional email envelope data for framework-neutral Ashlar messages.
/// </summary>
public sealed record EmailMessageOptions
{
    /// <summary>
    /// Gets or sets the from value.
    /// </summary>
    public string? From { get; init; }

    /// <summary>
    /// Gets or sets the reply to value.
    /// </summary>
    public string? ReplyTo { get; init; }

    /// <summary>
    /// Gets or sets the cc value.
    /// </summary>
    public string? Cc { get; init; }

    /// <summary>
    /// Gets or sets the bcc value.
    /// </summary>
    public string? Bcc { get; init; }

    /// <summary>
    /// Gets or sets the headers value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    /// <summary>
    /// Gets or sets the metadata value.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
