# Ashlar.Email.Smtp

SMTP email delivery for Ashlar using MailKit. Use it as a direct `IEmailSender` or as the transport for the PostgreSQL email outbox.

## Installation

```bash
dotnet add package Ashlar.Email.Smtp
```

## Usage

### Direct SMTP Sender

Use this if you want to send emails immediately through SMTP without an outbox.

```csharp
services.AddAshlarSmtpEmailSender(options =>
{
    options.Host = "smtp.example.com";
    options.Port = 587;
    options.Username = "user@example.com";
    options.Password = "your-password";
    options.DefaultFromAddress = "noreply@example.com";
});
```

### With PostgreSQL Outbox

Use this for reliable background email delivery.

```csharp
services.AddAshlarSmtpEmailTransport(options =>
{
    options.Host = "smtp.example.com";
    options.Port = 587;
    options.Username = "user@example.com";
    options.Password = "your-password";
    options.DefaultFromAddress = "noreply@example.com";
});

services.AddAshlarPostgresEmailOutboxHostedService<SmtpEmailTransport>();
```

### Configuration Example (appsettings.json)

```json
{
  "Ashlar": {
    "Smtp": {
      "Host": "smtp.example.com",
      "Port": 587,
      "Username": "user@example.com",
      "Password": "your-password",
      "DefaultFromAddress": "noreply@example.com",
      "SecurityOptions": "StartTls",
      "Timeout": 10000
    }
  }
}
```

```csharp
services.AddAshlarSmtpEmailTransport(context.Configuration.GetSection("Ashlar:Smtp").Bind);
services.AddAshlarPostgresEmailOutboxHostedService<SmtpEmailTransport>();
```

## Security

- Passwords are never logged.
- Exceptions are sanitized to avoid leaking credentials.
- Email headers are validated against injection attacks.

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence and email outbox support.
- `Ashlar.AspNetCore`: ASP.NET Core session authentication and authorization integration.
