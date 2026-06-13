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
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the security options for the SMTP connection.
    /// </summary>
    public SecureSocketOptions SecurityOptions { get; set; } = SecureSocketOptions.StartTls;

    /// <summary>
    /// Gets or sets the default "From" address if none is provided in the message.
    /// </summary>
    public string? DefaultFromAddress { get; set; }

    /// <summary>
    /// Gets or sets the connection timeout.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Validates SMTP email options.
    /// </summary>
    /// <param name="options">The options to validate.</param>
    /// <returns><see langword="true" /> when the options are valid.</returns>
    public static bool Validate(SmtpEmailOptions? options)
    {
        if (options == null || string.IsNullOrWhiteSpace(options.Host))
        {
            return false;
        }

        if (options.Port <= 0)
        {
            return false;
        }

        if (options.Timeout.TotalMilliseconds is < 1 or > int.MaxValue)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(options.Username) && string.IsNullOrWhiteSpace(options.Password))
        {
            return false;
        }

        return true;
    }
}
