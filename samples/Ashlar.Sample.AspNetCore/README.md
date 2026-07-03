# Ashlar ASP.NET Core Sample

This sample is a small reference application for composing Ashlar in an ASP.NET Core app. It uses PostgreSQL persistence, Data Protection secret protection, Ashlar session cookies, magic-link and email-code sign-in, passkeys, optional Google OIDC sign-in/linking/invitation registration, optional GitHub OAuth sign-in/linking, bootstrap setup, invitations, authorization grants, scoped ASP.NET Core policies, authenticator app verification, recovery codes, email verification, email change, session management, the PostgreSQL email outbox, cleanup service, audit sink, and rate limiter.

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

The sample accepts an `X-Tenant-Id` request header as a demo-only tenant selector so local tests can exercise tenant-scoped Ashlar flows. Treat this header as untrusted caller input. Production apps should derive tenant scope from an authenticated session, route or domain binding, membership lookup, or an authorization decision, not directly from a caller-controlled header.

### Optional Google OIDC

Google OIDC is disabled by default. The sample starts normally without Google configuration and hides all Google buttons when it is not configured.

To enable it, create a Google OAuth client in Google Cloud Console:

1. Open **APIs & Services -> Credentials**.
2. Choose **Create credentials -> OAuth client ID**.
3. For **Application type**, choose **Web application**.
4. Use any local name, such as `Ashlar Sample Local`.
5. Under **Authorised JavaScript origins**, add the sample origin:

```text
http://localhost:5000
```

6. Under **Authorised redirect URIs**, add the sample OIDC callback URL:

```text
http://localhost:5000/signin-oidc/Google
```

Google may take a few minutes to apply OAuth client changes. If you change `Ashlar:PublicAppUrl` or run the sample on a different port, update both Google Console values to match that origin and use `/signin-oidc/Google` as the redirect path.

Then copy the generated **Client ID** and **Client secret** into user secrets or environment variables. The sample project includes a `UserSecretsId`, so these commands write to your local profile and do not modify repository files. Do not commit real credentials.

```bash
dotnet user-secrets set "Authentication:Google:ClientId" "<client-id>" --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
dotnet user-secrets set "Authentication:Google:ClientSecret" "<client-secret>" --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

Optional hosted-domain restrictions can be configured as either a comma-separated value or an array:

```bash
dotnet user-secrets set "Authentication:Google:HostedDomains:0" "example.com" --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

Equivalent environment variables are:

```text
Authentication__Google__ClientId=<client-id>
Authentication__Google__ClientSecret=<client-secret>
Authentication__Google__HostedDomains__0=example.com
```

When enabled, the sample adds:

- **Sign in with Google** for users who already have a linked Google OIDC credential.
- **Sign up with Google** on invitation acceptance. The invitation token is preserved in ASP.NET Core authentication properties during the Google challenge and is only consumed after OIDC validation and Ashlar invitation registration succeed.
- **Link Google account** and **Unlink Google account** under Account -> Security. Both require fresh MFA when the current account has a usable eligible verification factor.

Google uses the configured Ashlar provider name `Google`. The sample displays only friendly linked/not-linked state from `AccountSecurityPosture.CredentialInventory`; it does not display provider keys, OIDC subjects, raw claims, or tokens. `Ashlar.OAuth` configures `SaveTokens = false`, and the sample does not persist OAuth access, refresh, or ID tokens.

### Optional GitHub OAuth

GitHub OAuth is disabled by default. The sample starts normally without GitHub configuration and hides all GitHub buttons when it is not configured.

To enable it, create a GitHub OAuth app:

1. Open **GitHub -> Settings -> Developer settings -> OAuth Apps**.
2. Choose **New OAuth App**.
3. Use any local name, such as `Ashlar Sample Local`.
4. Set **Homepage URL** to the sample origin:

```text
http://localhost:5000
```

5. Set **Authorization callback URL** to the sample OAuth callback URL:

```text
http://localhost:5000/signin-oauth/GitHub
```

If you change `Ashlar:PublicAppUrl` or run the sample on a different port, update both GitHub values to match that origin and use `/signin-oauth/GitHub` as the redirect path.

Then copy the generated **Client ID** and **Client secret** into user secrets or environment variables. Do not commit real credentials.

```bash
dotnet user-secrets set "Authentication:GitHub:ClientId" "<client-id>" --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
dotnet user-secrets set "Authentication:GitHub:ClientSecret" "<client-secret>" --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

Equivalent environment variables are:

```text
Authentication__GitHub__ClientId=<client-id>
Authentication__GitHub__ClientSecret=<client-secret>
```

When enabled, the sample adds:

- **Sign in with GitHub** for users who already have a linked GitHub OAuth credential.
- **Link GitHub account** and **Unlink GitHub account** under Account -> Security. Both require fresh MFA when the current account has a usable eligible verification factor.

GitHub uses the configured Ashlar provider name `GitHub` with `ProviderType.OAuth`. The sample displays only friendly linked/not-linked state from `AccountSecurityPosture.CredentialInventory`; it does not display GitHub provider keys, raw GitHub IDs, raw claims, access tokens, or profile JSON. `Ashlar.OAuth` configures `SaveTokens = false`, and the sample does not persist OAuth access or refresh tokens.

GitHub invitation acceptance is intentionally not enabled in this sample. The basic GitHub `/user` endpoint does not provide a reliable verified-email policy for invitation registration.

## Database Initialization

The sample calls `InitializeAshlarPostgresSchemaAsync()` at startup. When using a configured connection string, the database must already exist and the connection user must be able to create or update the Ashlar schema objects. When using the auto-container, the temporary database is created for you.

## Running

Configure a local bootstrap setup secret before starting the app. The sample project includes a `UserSecretsId`, so this writes to your local profile and does not modify repository files:

```bash
dotnet user-secrets set "Ashlar:Bootstrap:SetupSecret" "<local-setup-secret>" --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

Then run the sample:

```powershell
dotnet run --project samples/Ashlar.Sample.AspNetCore/Ashlar.Sample.AspNetCore.csproj
```

Ashlar hashes this secret for bootstrap authorization and the sample never returns or logs it.

Equivalent environment variables are:

```text
Ashlar__Bootstrap__SetupSecret=<local-setup-secret>
```

The sample fails fast at startup if `Ashlar:Bootstrap:SetupSecret` is not configured, because first-admin bootstrap intentionally has no insecure fallback.

## Walkthrough

Navigate to `http://localhost:5000` in your browser.

1. **Bootstrap**: Since the system starts uninitialized, you will see a bootstrap form. Enter an email, username, and the configured setup secret to initialize the system and automatically sign in as the first administrator.
2. **Dashboard**: Once signed in, you can view your project access and navigate to account or administration tasks.
3. **Authenticator app**: Go to Account → Security to enroll in TOTP. A QR code will be generated for your authenticator app. After verifying your first code, you can also generate recovery codes. When the sample asks for additional verification after magic-link sign-in, the current policy accepts an authenticator app code or recovery code.
4. **Step-up verification**: Sensitive account operations require fresh MFA. When a protected action needs step-up, the sample opens a modal for an authenticator app code or recovery code. Successful verification marks only the current Ashlar session fresh.
5. **Passkeys**: Use **Sign in with Passkey** on the dashboard to authenticate with a registered passkey. While signed in, open **Account → Security** to register, list, rename, and revoke passkeys. The sample shows authenticator apps, recovery codes, and passkeys as separate sign-in verification methods. Passkeys require HTTPS or localhost and a browser that supports WebAuthn. Passkeys are wired for primary sign-in and for passkey factor handshakes; passkey step-up can be validated manually through the browser WebAuthn factor endpoints. The automated smoke tests avoid hardware-backed WebAuthn.
6. **Google OIDC**: If Google is configured, use **Sign in with Google** for linked accounts, **Sign up with Google** for invitation-based registration, and **Account → Security** to link or unlink Google. Linking and unlinking require fresh MFA when an eligible verification factor is available.
7. **GitHub OAuth**: If GitHub is configured, use **Sign in with GitHub** for linked accounts and **Account → Security** to link or unlink GitHub. Linking and unlinking require fresh MFA when an eligible verification factor is available. GitHub invitation acceptance is not enabled.
8. **Email Verification**: If your email is unverified, click "Resend Verification Email" and check the console for the link.
9. **Email Change**: Use "Change Email" in your profile to request a new email address. This requires fresh MFA. Confirm the change via the link in the console.
10. **Session Management**: Go to Account → Security to view your active sessions. You can revoke a specific session or all other sessions with conditional fresh MFA when a usable factor exists.
11. **Invitations**: As an administrator, you can invite new users by entering their email address.
12. **Accepting Invitations**: Check the application console to find the (simulated) invitation email. Click the link provided to join the application. You will be automatically signed in as the new user.
13. **Authorization**: Use the administration section to grant "project.manage" permissions to other users for the "alpha" or "beta" projects. The dashboard dynamically updates to show where you have manager access.

## Fresh MFA in the sample

The sample registers the default fresh MFA policy in `AddAshlarAspNetCoreAuthorization` with a 10-minute freshness window and allows `totp`, `recovery_code`, and `passkey` factors:

```csharp
options.StepUp.FreshnessWindow = TimeSpan.FromMinutes(10);
options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Totp);
options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.RecoveryCode);
options.StepUp.AllowedFactors.Add(AuthenticationFactorTypes.Passkey);
options.RequireFreshMfa();
options.RequireFreshMfaIfAvailable();
```

Routes use `.RequireFreshMfa()` for high-risk sensitive operations: passkey registration/rename/revoke, TOTP reset, recovery-code generation, email change requests, and administrator disable/reactivate/session-revoke/MFA-reset actions. User-owned session revocation and Google/GitHub account link/unlink endpoints use `.RequireFreshMfaIfAvailable()` to demonstrate adaptive protection: users with a usable eligible additional verification factor must complete fresh step-up, while users without one are not locked out of revoking old devices or adding another sign-in method. Ordinary sign-in, email verification confirmation, invitation acceptance, account viewing, and session listing remain available with a normal authenticated session.

## CSRF protection in the sample

The sample registers ASP.NET Core antiforgery services and applies sample-local validation to cookie-authenticated unsafe browser mutations. Authenticated pages fetch a request token from `/api/antiforgery/token`, then send it on same-origin `POST` and `DELETE` requests with the `X-CSRF-TOKEN` header. Logout forms are submitted through the same helper so sign-out is also protected.

The intentionally unauthenticated bootstrap, sign-in, MFA handshake, invitation acceptance, and token-bearing email confirmation routes do not require a CSRF token. Those flows rely on one-time tokens or handshake state and must remain reachable before a full authenticated browser session exists.

The account and administration pages render Ashlar's account security posture model. They show sign-in methods separately from additional verification, use friendly labels such as "Authenticator app", "Recovery codes", and "Passkeys", and show whether protected actions are available or blocked until setup.

Normal invitation, magic-link, and account tokens are sent through the PostgreSQL email outbox. `DevelopmentEmailTransport` logs full email bodies to the console so local callback links are easy to click or copy.

The cleanup hosted service and email outbox dispatcher start with the application. The sample intentionally uses a development email transport that exposes token-bearing email bodies; replace `DevelopmentEmailTransport` before using this composition outside local development.

## Smoke Tests

`tests/Ashlar.Postgres.Tests` includes a net10-only ASP.NET Core smoke test for this sample. It hosts the real sample app with `WebApplicationFactory<Program>`, supplies an isolated PostgreSQL database from the existing Testcontainers fixture, disables background hosted loops, and inspects `ashlar_email_outbox` directly instead of using SMTP.

The smoke test is intentionally thin: it proves the composed routing, DI, session cookie authentication, Postgres persistence, outbox-backed email flows, bootstrap, invitations, scoped authorization grants, email verification/change, authenticator app enrollment, recovery-code step-up, fresh-MFA protected sample operations, session endpoints, and conditional Google OIDC and GitHub OAuth sample wiring work together. Google and GitHub smoke coverage uses configuration and local safe-failure/challenge checks only; it never calls Google or GitHub and does not require real provider credentials. Passkey endpoints require manual browser WebAuthn validation and are not exercised as an automated hardware-backed flow. The smoke test does not replace the lower-level unit and integration tests that cover branch-level behavior.
