using Ashlar.Messaging;
using Ashlar.Security;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Ashlar.Email.Smtp;

/// <summary>
/// SMTP implementation of <see cref="IEmailTransport"/> using MailKit.
/// </summary>
public class SmtpEmailTransport : IEmailTransport
{
    private static readonly HashSet<string> ReservedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "From",
        "Sender",
        "To",
        "Subject",
        "Reply-To",
        "Cc",
        "Bcc",
        "Date",
        "Return-Path",
        "Alternate-Recipient"
    };

    private readonly SmtpEmailOptions _options;

    /// <summary>
    /// Initializes a new instance of the smtp email transport class.
    /// </summary>
    /// <param name="options">The options value.</param>
    public SmtpEmailTransport(IOptions<SmtpEmailOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        if (!SmtpEmailOptions.Validate(_options))
        {
            throw new ArgumentException("SMTP email options are invalid.", nameof(options));
        }
    }

    /// <summary>
    /// Delivers an email message through the configured SMTP server.
    /// </summary>
    /// <param name="message">The email message.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous delivery operation.</returns>
    public async Task DeliverAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        var host = _options.Host;
        using var mimeMessage = CreateMimeMessage(message);
        var sender = mimeMessage.From.Mailboxes.Single();
        var recipients = mimeMessage.To.Mailboxes
            .Concat(mimeMessage.Cc.Mailboxes)
            .Concat(mimeMessage.Bcc.Mailboxes)
            .DistinctBy(mailbox => mailbox.Address, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (recipients.Length == 0)
        {
            throw new InvalidOperationException("At least one recipient address must be provided.");
        }

        using var client = CreateSmtpClient();
        client.Timeout = (int)_options.Timeout.TotalMilliseconds;

        try
        {
            await client.ConnectAsync(host, _options.Port, _options.SecurityOptions, cancellationToken);

            var username = _options.Username;
            if (!string.IsNullOrWhiteSpace(username))
            {
                await client.AuthenticateAsync(username, _options.Password, cancellationToken);
            }

            await client.SendAsync(mimeMessage, sender, recipients, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (SecretRedactor.ContainsSecret(ex, _options.Password))
        {
            var redactedDetails = SecretRedactor.Redact(ex, _options.Password);
            throw new InvalidOperationException($"Failed to deliver email via SMTP. Exception details redacted for security: {redactedDetails}");
        }
    }

    /// <summary>
    /// Creates a new <see cref="ISmtpClient"/>.
    /// </summary>
    /// <returns>The operation result.</returns>
    protected virtual ISmtpClient CreateSmtpClient()
    {
        return new SmtpClient();
    }

    private MimeMessage CreateMimeMessage(EmailMessage message)
    {
        var mimeMessage = new MimeMessage();

        var from = message.From ?? _options.DefaultFromAddress;
        if (string.IsNullOrWhiteSpace(from))
        {
            throw new InvalidOperationException("A 'From' address must be provided either in the EmailMessage or in SmtpEmailOptions.");
        }

        mimeMessage.From.Add(MailboxAddress.Parse(from));
        mimeMessage.To.AddRange(InternetAddressList.Parse(message.To));

        if (!string.IsNullOrWhiteSpace(message.ReplyTo))
        {
            mimeMessage.ReplyTo.AddRange(InternetAddressList.Parse(message.ReplyTo));
        }

        if (!string.IsNullOrWhiteSpace(message.Cc))
        {
            mimeMessage.Cc.AddRange(InternetAddressList.Parse(message.Cc));
        }

        if (!string.IsNullOrWhiteSpace(message.Bcc))
        {
            mimeMessage.Bcc.AddRange(InternetAddressList.Parse(message.Bcc));
        }

        mimeMessage.Subject = message.Subject;

        var bodyBuilder = new BodyBuilder();
        if (message.TextBody != null)
        {
            bodyBuilder.TextBody = message.TextBody;
        }

        if (message.HtmlBody != null)
        {
            bodyBuilder.HtmlBody = message.HtmlBody;
        }

        mimeMessage.Body = bodyBuilder.ToMessageBody();

        if (message.Headers != null)
        {
            foreach (var header in message.Headers)
            {
                if (IsReservedHeader(header.Key) || !_options.AllowedCustomHeaders.Contains(header.Key))
                {
                    continue;
                }

                mimeMessage.Headers.Add(header.Key, header.Value);
            }
        }

        return mimeMessage;
    }

    private static bool IsReservedHeader(string name) =>
        ReservedHeaders.Contains(name) || name.StartsWith("Resent-", StringComparison.OrdinalIgnoreCase);
}
