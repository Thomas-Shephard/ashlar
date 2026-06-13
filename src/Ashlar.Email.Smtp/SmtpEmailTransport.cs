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

            await client.SendAsync(mimeMessage, cancellationToken);
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

        mimeMessage.From.AddRange(InternetAddressList.Parse(from));
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
                if (IsReservedHeader(header.Key))
                {
                    continue;
                }

                mimeMessage.Headers.Add(header.Key, header.Value);
            }
        }

        return mimeMessage;
    }

    private static bool IsReservedHeader(string name) =>
        name.Equals("From", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("To", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Subject", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Reply-To", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Cc", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Bcc", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Date", StringComparison.OrdinalIgnoreCase);
}
