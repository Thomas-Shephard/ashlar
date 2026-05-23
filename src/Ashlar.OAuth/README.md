# Ashlar.OAuth

ASP.NET Core OAuth and OpenID Connect sign-in integration for Ashlar.

This package registers ASP.NET Core OpenID Connect handlers, maps validated external principals to Ashlar `ExternalIdentityAssertion` values, and delegates sign-in to Ashlar's authentication pipeline.

It does not create users, automatically link credentials, persist OAuth tokens, issue Ashlar session cookies, or provide UI. Applications decide onboarding/linking policy and issue their normal Ashlar session after a successful result.

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

Passing hosted domains to `AddGoogle` adds Google's `hd` login UI hint and enforces the validated returned `hd` claim against the allowed domains before Ashlar login continues.

Microsoft Entra ID:

```csharp
using Ashlar.OAuth.Providers.Microsoft;

options.AddMicrosoft("contoso.onmicrosoft.com", ...);
```

Builds authority `https://login.microsoftonline.com/{tenant}/v2.0`. The tenant segment is explicit and should match the application's intended sign-in audience.

## Redirects And Completion

By default, provider callback paths are:

```text
/signin-oidc/{scheme}
```

For example, register `https://localhost:5001/signin-oidc/Google` with Google for local development.

Start sign-in by challenging the provider scheme:

```csharp
await httpContext.ChallengeAsync("Google", new AuthenticationProperties
{
    RedirectUri = "/signin/google/callback"
});
```

Complete sign-in with `AshlarExternalSignInService`, then issue the Ashlar session:

```csharp
var result = await externalSignIn.CompleteOidcSignInAsync(httpContext, "Google");
if (result.Succeeded && result.Authentication?.User != null)
{
    await signInManager.SignInAsync(httpContext, result.Authentication.User.Id);
}
```

## Security Notes

- ASP.NET Core's OpenID Connect handler performs state, nonce, code exchange, token validation, issuer validation, audience validation, signing key validation, and expiry validation.
- Ashlar uses OIDC `sub` as the stable provider key, not email.
- Google `hd` is an organization/domain signal, not an Ashlar tenant. When domains are passed to `AddGoogle`, Ashlar.OAuth validates the returned `hd` claim before completing sign-in.
- `AuthenticationContext.TenantId` remains Ashlar's tenant context and should be supplied by the app when completing sign-in for a tenant-aware flow.
- Do not log or persist authorization codes, access tokens, refresh tokens, ID tokens, raw claim payloads, or cookies in this slice.
