using MailKit.Security;

namespace Ashlar.Email.Smtp;

/// <summary>
/// Options for SMTP email transport.
/// </summary>
public sealed class SmtpEmailOptions
{
    /// <summary>
    /// Gets or sets the SMTP server host.
    /// </summary>
    public required string Host { get; set; }

    /// <summary>
    /// Gets or sets the SMTP server port.
    /// </summary>
    public int Port { get; set; } = 587;

    /// <summary>
    /// Gets or sets the username for authentication.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Gets or sets the password for authentication.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Gets or sets the security options for the SMTP connection.
    /// </summary>
    public SecureSocketOptions SecurityOptions { get; set; } = SecureSocketOptions.StartTls;

    /// <summary>
    /// Gets or sets the default "From" address if none is provided in the message.
    /// </summary>
    public string? DefaultFromAddress { get; set; }

    /// <summary>
    /// Gets or sets the connection timeout in milliseconds.
    /// </summary>
    public int Timeout { get; set; } = 10000;

    /// <summary>
    /// Validates the current options.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when options are invalid.</exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host))
        {
            throw new ArgumentException("SMTP Host is required.");
        }

        if (Port <= 0)
        {
            throw new ArgumentException("SMTP Port must be a positive integer.");
        }

        if (!string.IsNullOrWhiteSpace(Username) && string.IsNullOrWhiteSpace(Password))
        {
            throw new ArgumentException("SMTP Password is required when Username is provided.");
        }
    }
}
