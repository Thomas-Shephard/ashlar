# Ashlar.OAuth

ASP.NET Core OAuth and OpenID Connect credential integration for Ashlar.

This package registers ASP.NET Core OpenID Connect handlers and maps validated external principals to Ashlar `ExternalIdentityAssertion` values.

It does not provide UI, persist OAuth tokens, issue Ashlar session cookies, bypass MFA orchestration, or allow open self-registration. Applications decide routing and issue their normal Ashlar session only after their authentication orchestration succeeds.

## Setup

```csharp
using Ashlar.OAuth.Providers.Google;

builder.Services.AddAshlarOAuth(options =>
{
    options.AddGoogle(["yourcompany.com"], oidc =>
    {
        oidc.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        oidc.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    });
});
```

For a generic OIDC provider:

```csharp
builder.Services.AddAshlarOAuth(options =>
{
    options.AddOidcProvider("Contoso", oidc =>
    {
        oidc.Authority = "https://login.contoso.example";
        oidc.ClientId = builder.Configuration["Authentication:Contoso:ClientId"];
        oidc.ClientSecret = builder.Configuration["Authentication:Contoso:ClientSecret"];
        oidc.ResponseType = "code";
        oidc.Scope.Add("openid");
        oidc.Scope.Add("profile");
        oidc.Scope.Add("email");
    });
});
```

## Presets

Google:

```csharp
using Ashlar.OAuth.Providers.Google;

options.AddGoogle(...);
```

Configures provider name `Google`, authority `https://accounts.google.com`, authorization code flow, and `openid profile email` scopes. Ashlar uses Google's stable `sub` claim as the provider key. Email claims are copied when present but are not used as the provider key.

Passing hosted domains to `AddGoogle` adds Google's `hd` login UI hint and enforces the validated returned `hd` claim against the allowed domains before Ashlar credential authentication continues.

Apple:

```csharp
using Ashlar.OAuth.Providers.Apple;

options.AddApple(oidc =>
{
    oidc.ClientId = builder.Configuration["Authentication:Apple:ClientId"];
    oidc.ClientSecret = builder.Configuration["Authentication:Apple:ClientSecret"];
});
```

Configures provider name `Apple`, authority `https://appleid.apple.com`, authorization code flow, and `openid email name` scopes. Ashlar uses Apple's stable `sub` claim as the provider key. Apple client secrets are normally application-generated JWTs; production apps must configure generation, rotation, and storage themselves through `OpenIdConnectOptions`, for example by setting `ClientSecret` in the configure callback.

Apple profile claims are display hints only. The `name` value may only be returned during the first authorization, and `email` may be an Apple private relay address. Invitation email matching uses the generic verified-email policy unless the application replaces `IOidcInvitationEmailMatchPolicy`.

Microsoft Entra ID:

```csharp
using Ashlar.OAuth.Providers.Microsoft;

options.AddMicrosoft("contoso.onmicrosoft.com", ...);
```

Builds authority `https://login.microsoftonline.com/{tenant}/v2.0`. The tenant segment is explicit and should match the application's intended sign-in audience.

For personal Microsoft accounts, use a sign-in/linking preset:

```csharp
options.AddMicrosoftPersonalAccounts();
```

This uses the Microsoft `consumers` authority.

For work, school, and personal Microsoft accounts through the shared Microsoft account picker:

```csharp
options.AddMicrosoftAnyAccount();
```

This uses the Microsoft `common` authority. The application registration must allow the selected Microsoft account audiences, and apps should keep their own issuer/tenant admission policy aligned with that audience. For example, enforce an allowed `tid` or `iss` in `OpenIdConnectOptions.Events.OnTokenValidated` when only specific Microsoft tenants should be admitted. The shared Microsoft presets use issuer-qualified credential keys so the same provider name cannot collide on a bare `sub` issued by different Microsoft authorities.

## Redirects And Completion

By default, provider callback paths are:

```text
/signin-oidc/{scheme}
```

For example, register `https://localhost:5001/signin-oidc/Google` with Google for local development.

Start an external OIDC challenge with the provider scheme:

```csharp
await httpContext.ChallengeAsync("Google", new AuthenticationProperties
{
    RedirectUri = "/signin/google/callback"
});
```

For MFA-aware applications, complete the callback only to an Ashlar assertion, pass that assertion through `IAuthenticationOrchestrator`, and issue the Ashlar session only after orchestration succeeds:

```csharp
var assertionResult = await externalCredentials.CompleteOidcAssertionAsync(httpContext, "Google");
if (!assertionResult.Succeeded || assertionResult.Assertion == null)
{
    return Results.Redirect("/signin?external=failed");
}

var authentication = await orchestrator.AuthenticateAsync(
    httpContext.ToAuthenticationContext(),
    assertionResult.Assertion,
    cancellationToken: cancellationToken);

if (authentication.Status == MfaAuthenticationStatus.MfaRequired)
{
    return RenderMfaChallenge(authentication.HandshakeToken, authentication.RequiredFactors);
}

if (authentication.Status != MfaAuthenticationStatus.Succeeded || authentication.User == null)
{
    return Results.Redirect("/signin?external=failed");
}

await signInManager.SignInAsync(httpContext, authentication.User.Id, cancellationToken);
return Results.Redirect("/");
```

`CompleteOidcAssertionAsync` validates the temporary external ticket, checks that it was issued for the expected configured provider, clears the external cookie, and returns a mapped `ExternalIdentityAssertion`. A successful assertion result means the external OIDC credential was validated and mapped; it does not mean an application session may be issued.

`AshlarExternalCredentialAuthenticationService.CompleteOidcCredentialAuthenticationAsync` is a lower-level helper that maps the OIDC credential and calls Ashlar's authentication pipeline directly. It still does not issue an application session or cookie. Use it only when the host application deliberately treats the returned Ashlar authentication response as the complete credential-authentication decision. Applications with MFA policy must not issue sessions directly from external credential validation; use `CompleteOidcAssertionAsync` and the host orchestration pipeline instead.

## Profile Hints

Applications can map conservative display hints from a principal that has already been validated by the configured OpenID Connect handler:

```csharp
var profile = AshlarOidcProfileMapper.Map(validatedPrincipal);
var displayName = profile.DisplayName;
```

Profile values are display hints only. They are not identity assertions, provider keys, authorization inputs, tenancy decisions, or instructions to mutate an Ashlar user. Callers must only pass principals that have already been validated by the configured OIDC handler; do not build principals from request data or unvalidated tokens.

`Email` and `EmailVerified` are profile hints and do not replace invitation email match policy. Invitation registration still uses the configured `IOidcInvitationEmailMatchPolicy`.

## Security Notes

- ASP.NET Core's OpenID Connect handler performs state, nonce, code exchange, token validation, audience validation, signing key validation, and expiry validation according to the configured authority and token validation parameters.
- Ashlar uses OIDC `sub` as the stable provider key, not email. For shared-authority providers that can admit multiple issuers, provider presets can qualify the key with `iss` as well as `sub`.
- Google `hd` is an organization/domain signal, not an Ashlar tenant. When domains are passed to `AddGoogle`, Ashlar.OAuth validates the returned `hd` claim before external credential authentication completes.

## Invitation registration

`AshlarOidcInvitationRegistrationService` accepts an existing Ashlar invitation token with a validated OIDC identity and then links the OIDC credential to the accepted Ashlar user. It does not sign the user in automatically. Overloads that accept a raw `ClaimsPrincipal` assume the caller has already validated that principal with the same configured OIDC provider; do not pass principals built from request data or unvalidated JWTs. Use the ASP.NET Core authentication-result overloads when completing normal external-auth callbacks.

By default, `StandardOidcVerifiedEmailMatchPolicy` requires generic OIDC providers to match a standard `email` claim with `email_verified=true` before the invitation is consumed. Microsoft tenant providers registered with `AddMicrosoft` automatically use the provider-specific policy from `Providers.Microsoft`, matching the invitation email against Microsoft sign-in/email identity claims such as `email`, `preferred_username`, `upn`, or `unique_name`, because Microsoft identity platform ID tokens do not consistently emit standard OIDC `email_verified`. This Microsoft policy relies on the configured tenant/provider trust and identity claim validation; it is not a general standards-level verified-email proof. `AddMicrosoft` requires a tenant-specific authority and rejects `common`, `organizations`, and `consumers`; use separate provider names for separate tenants. `AddMicrosoftPersonalAccounts` and `AddMicrosoftAnyAccount` are sign-in/linking presets and do not opt into the Microsoft invitation email policy. Applications with stricter Microsoft requirements can replace `IOidcInvitationEmailMatchPolicy`. Missing email, unverified email, mismatched email, invalid tokens, provider mismatch, and link failures are returned as explicit statuses for application branching. Public UI should still use generic failure messages.

- `AuthenticationContext.TenantId` remains Ashlar's tenant context and should be supplied by the app when completing tenant-aware sign-in or invitation registration flows. Invitation registration rejects a context tenant that does not match the invitation tenant.
- Do not log or persist authorization codes, access tokens, refresh tokens, ID tokens, raw claim payloads, or cookies in this slice.
