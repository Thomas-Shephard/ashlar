# Ashlar ASP.NET Core Sample

This sample is a small reference application for composing Ashlar in an ASP.NET Core app. It uses PostgreSQL persistence, Data Protection secret protection, Ashlar session cookies, magic-link and email-code sign-in, bootstrap setup, invitations, authorization grants, scoped ASP.NET Core policies, TOTP MFA, recovery codes, email verification, email change, session management, the PostgreSQL email outbox, cleanup service, audit sink, and rate limiter.

The entire sample can be exercised directly through the web UI at `http://localhost:5000`.

## Prerequisites

- .NET SDK from `global.json`
- Docker, or PostgreSQL with a configured connection string

## Configuration

The sample starts a disposable `postgres:15-alpine` container when `Ashlar:ConnectionString` is not configured. To use your own database, configure the `Ashlar` section in `appsettings.json`, user secrets, or environment variables:

```json
{
  "Ashlar": {
    "AppName": "Ashlar Sample",
    "ConnectionString": "Host=localhost;Port=5432;Database=ashlar_sample;Username=postgres;Password=postgres",
    "PublicAppUrl": "http://localhost:5000",
    "Cookie": {
      "Name": "Ashlar.Sample",
      "Secure": false
    },
    "Outbox": {
      "PollingInterval": "00:00:01",
      "BatchSize": 25
    },
    "Cleanup": {
      "CleanupInterval": "01:00:00"
    }
  }
}
```

For local HTTP testing, set `Ashlar:Cookie:Secure` to `false`, use an HTTP `PublicAppUrl`, and do not use a `__Host-` cookie name. `__Host-` cookies require `SecurePolicy.Always`.

## Database Initialization

The sample calls `InitializeAshlarPostgresSchemaAsync()` at startup. When using a configured connection string, the database must already exist and the connection user must be able to create or update the Ashlar schema objects. When using the auto-container, the temporary database is created for you.

## Running

```bash
dotnet run --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

## Walkthrough

Navigate to `http://localhost:5000` in your browser.

1. **Bootstrap**: Since the system starts uninitialized, you will see a bootstrap form. Enter an email and username to initialize the system and automatically sign in as the first administrator.
2. **Dashboard**: Once signed in, you can view your profile, manage MFA settings, and perform administrative tasks.
3. **MFA Setup**: Go to "MFA Settings" to enroll in TOTP. A QR code will be generated for your authenticator app. After verifying your first code, you can also generate recovery codes.
4. **Email Verification**: If your email is unverified, click "Resend Verification Email" and check the console for the link.
5. **Email Change**: Use "Change Email" in your profile to request a new email address. Confirm the change via the link in the console.
6. **Session Management**: View your active sessions at the bottom of the dashboard. You can revoke specific sessions or all other sessions.
7. **Invitations**: As an administrator, you can invite new users by entering their email address.
8. **Accepting Invitations**: Check the application console to find the (simulated) invitation email. Click the link provided to join the application. You will be automatically signed in as the new user.
9. **Authorization**: Use the administration section to grant "project.manage" permissions to other users for the "alpha" or "beta" projects. The dashboard dynamically updates to show where you have manager access.

Normal invitation, magic-link, and account tokens are sent through the PostgreSQL email outbox. `DevelopmentEmailTransport` logs full email bodies to the console so local callback links are easy to click or copy.

The cleanup hosted service and email outbox dispatcher start with the application. The sample intentionally uses a development email transport that exposes token-bearing email bodies; replace `DevelopmentEmailTransport` before using this composition outside local development.
