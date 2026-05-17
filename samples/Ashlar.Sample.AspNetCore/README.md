# Ashlar ASP.NET Core Sample

This sample is a small reference application for composing Ashlar in an ASP.NET Core app. It uses PostgreSQL persistence, Data Protection secret protection, Ashlar session cookies, magic-link and email-code sign-in, passkeys, bootstrap setup, invitations, authorization grants, scoped ASP.NET Core policies, authenticator app verification, recovery codes, email verification, email change, session management, the PostgreSQL email outbox, cleanup service, audit sink, and rate limiter.

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

The sample derives its allowed callback URIs from `PublicAppUrl` and the fixed magic-link, invitation, email verification, and email change paths it emits. Links are built from this configured value, not from request-supplied return URLs. Keep `PublicAppUrl` to the exact local or public origin you expect, without query strings or fragments. In production, configure an HTTPS public URL and keep `Ashlar:Cookie:Secure` enabled.

## Database Initialization

The sample calls `InitializeAshlarPostgresSchemaAsync()` at startup. When using a configured connection string, the database must already exist and the connection user must be able to create or update the Ashlar schema objects. When using the auto-container, the temporary database is created for you.

## Running

```bash
dotnet run --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

## Walkthrough

Navigate to `http://localhost:5000` in your browser.

1. **Bootstrap**: Since the system starts uninitialized, you will see a bootstrap form. Enter an email and username to initialize the system and automatically sign in as the first administrator.
2. **Dashboard**: Once signed in, you can view your project access and navigate to account or administration tasks.
3. **Authenticator app**: Go to Account → Security to enroll in TOTP. A QR code will be generated for your authenticator app. After verifying your first code, you can also generate recovery codes. When the sample asks for additional verification after magic-link sign-in, the current policy accepts an authenticator app code or recovery code.
4. **Step-up verification**: Sensitive account operations require fresh MFA. When a protected action needs step-up, the sample opens a modal for an authenticator app code or recovery code. Successful verification marks only the current Ashlar session fresh.
5. **Passkeys**: Use **Sign In With Passkey** on the dashboard to authenticate with a registered passkey. While signed in, open **Account → Security** to register, list, rename, and revoke passkeys. The sample shows authenticator apps, recovery codes, and passkeys as separate sign-in verification methods. Passkeys require HTTPS or localhost and a browser that supports WebAuthn. Passkeys are wired for primary sign-in and for passkey factor handshakes; passkey step-up can be validated manually through the browser WebAuthn factor endpoints. The automated smoke tests avoid hardware-backed WebAuthn.
6. **Email Verification**: If your email is unverified, click "Resend Verification Email" and check the console for the link.
7. **Email Change**: Use "Change Email" in your profile to request a new email address. This requires fresh MFA. Confirm the change via the link in the console.
8. **Session Management**: Go to Account → Security to view your active sessions. You can revoke specific sessions or all other sessions; revoking all other sessions requires fresh MFA.
9. **Invitations**: As an administrator, you can invite new users by entering their email address.
10. **Accepting Invitations**: Check the application console to find the (simulated) invitation email. Click the link provided to join the application. You will be automatically signed in as the new user.
11. **Authorization**: Use the administration section to grant "project.manage" permissions to other users for the "alpha" or "beta" projects. The dashboard dynamically updates to show where you have manager access.

## Fresh MFA in the sample

The sample registers the default fresh MFA policy in `AddAshlarAspNetCoreAuthorization` with a 10-minute freshness window and allows `totp`, `recovery_code`, and `passkey` factors:

```csharp
options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(10);
options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.RecoveryCode);
options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
options.RequireFreshMfa();
```

Routes use `.RequireFreshMfa()` for sensitive operations: passkey registration/rename/revoke, TOTP reset, recovery-code generation, email change requests, revoking other sessions, and administrator disable/reactivate/session-revoke/MFA-reset actions. Ordinary sign-in, sign-out, email verification, invitation acceptance, account viewing, and session listing remain available with a normal authenticated session.

Normal invitation, magic-link, and account tokens are sent through the PostgreSQL email outbox. `DevelopmentEmailTransport` logs full email bodies to the console so local callback links are easy to click or copy.

The cleanup hosted service and email outbox dispatcher start with the application. The sample intentionally uses a development email transport that exposes token-bearing email bodies; replace `DevelopmentEmailTransport` before using this composition outside local development.

## Smoke Tests

`tests/Ashlar.Postgres.Tests` includes a net10-only ASP.NET Core smoke test for this sample. It hosts the real sample app with `WebApplicationFactory<Program>`, supplies an isolated PostgreSQL database from the existing Testcontainers fixture, disables background hosted loops, and inspects `ashlar_email_outbox` directly instead of using SMTP.

The smoke test is intentionally thin: it proves the composed routing, DI, session cookie authentication, Postgres persistence, outbox-backed email flows, bootstrap, invitations, scoped authorization grants, email verification/change, authenticator app enrollment, recovery-code step-up, fresh-MFA protected sample operations, and session endpoints work together. Passkey endpoints require manual browser WebAuthn validation and are not exercised as an automated hardware-backed flow. The smoke test does not replace the lower-level unit and integration tests that cover branch-level behavior.
