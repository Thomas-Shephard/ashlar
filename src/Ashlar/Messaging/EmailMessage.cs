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

    public string To { get; }

    public string Subject { get; }

    public string? TextBody { get; }

    public string? HtmlBody { get; }

    public string? From { get; }

    public string? ReplyTo { get; }

    public string? Cc { get; }

    public string? Bcc { get; }

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

    public string? Cc { get; init; }

    public string? Bcc { get; init; }

    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    public IReadOnlyDictionary<string, string>? Metadata { get; init; }
}
