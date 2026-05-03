using System.Collections.ObjectModel;

namespace Ashlar.Messaging;

/// <summary>
/// Represents an email message produced by framework-neutral Ashlar flows.
/// </summary>
public sealed record EmailMessage
{
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

        To = to;
        Subject = subject;
        TextBody = textBody;
        HtmlBody = htmlBody;
        From = options?.From;
        ReplyTo = options?.ReplyTo;
        Headers = options?.Headers is null ? null : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(options.Headers));
        Metadata = options?.Metadata is null ? null : new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(options.Metadata));
    }

    public string To { get; }

    public string Subject { get; }

    public string? TextBody { get; }

    public string? HtmlBody { get; }

    public string? From { get; }

    public string? ReplyTo { get; }

    public IReadOnlyDictionary<string, string>? Headers { get; }

    public IReadOnlyDictionary<string, string>? Metadata { get; }
}

/// <summary>
/// Optional email envelope data for framework-neutral Ashlar messages.
/// </summary>
public sealed record EmailMessageOptions
{
    public string? From { get; init; }

    public string? ReplyTo { get; init; }

    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
