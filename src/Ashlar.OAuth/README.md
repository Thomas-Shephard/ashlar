# Ashlar.OAuth

ASP.NET Core OAuth and OpenID Connect credential integration for Ashlar.

This package registers ASP.NET Core OpenID Connect and OAuth handlers and maps validated external principals to Ashlar `ExternalIdentityAssertion` values.

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

Generic OIDC providers use issuer-qualified provider keys by default: Ashlar derives the credential key from the validated `iss` and `sub` claims. This avoids collisions when one configured Ashlar provider can admit identities from more than one issuer. Applications with a fixed single-issuer provider can opt into subject-only keys explicitly with `AshlarOidcProviderKeyMode.Subject`.

For a generic non-OIDC OAuth2 provider:

```csharp
builder.Services.AddAshlarOAuth(options =>
{
    options.AddOAuth2Provider("Contoso", "uid", oauth =>
    {
        oauth.AuthorizationEndpoint = "https://oauth.contoso.example/authorize";
        oauth.TokenEndpoint = "https://oauth.contoso.example/token";
        oauth.UserInformationEndpoint = "https://oauth.contoso.example/user";
    });
});
```

The second argument to `AddOAuth2Provider` is the claim type Ashlar will use as the stable provider key after the OAuth handler has validated and populated the external principal. The default is `id`, which matches GitHub, but other providers may require values such as `sub`, `uid`, or `user_id`. Do not configure an email, username, login, or display name claim as the provider key.

`AddOAuth2Provider` rejects common mutable or non-unique claim names by default. If an unusual provider uses one of those claim names for a documented stable immutable user id, `AddOAuth2ProviderWithUnsafeProviderKeyClaimType` is available as an explicit opt-in; callers own the risk and should only use it after confirming the provider contract.

## Presets

GitHub:

```csharp
using Ashlar.OAuth.Providers.GitHub;

options.AddGitHub(oauth =>
{
    oauth.ClientId = builder.Configuration["Authentication:GitHub:ClientId"];
    oauth.ClientSecret = builder.Configuration["Authentication:GitHub:ClientSecret"];
});
```

GitHub is OAuth2, not OpenID Connect. The preset uses ASP.NET Core's OAuth handler, authorization endpoint `https://github.com/login/oauth/authorize`, token endpoint `https://github.com/login/oauth/access_token`, and user endpoint `https://api.github.com/user`. It uses the authorization code flow with ASP.NET Core's state/correlation protection and enables S256 PKCE by default. By default it requests no extra scopes; ASP.NET Core sends an empty `scope` value for the default challenge. The basic `/user` response includes GitHub's stable numeric `id`, which Ashlar uses as the provider key. Ashlar does not use GitHub email, username, login, or display name as the provider key.

The preset maps safe profile hints from `/user`: `id`, `login`, `name`, and `email` when GitHub returns them. GitHub email may be absent or private, and the basic `/user` endpoint is not a verified-email policy. This slice does not call `/user/emails`.

Use the normal ASP.NET Core OAuth callback flow for GitHub sign-in and linking so the preset revalidates the user's identity with `/user` on every sign-in. Raw-principal overloads are for principals already validated by trusted infrastructure; do not build GitHub OAuth principals from request data, cached profile JSON, or stale tokens.

Google:

```csharp
using Ashlar.OAuth.Providers.Google;

options.AddGoogle(...);
```

Configures provider name `Google`, authority `https://accounts.google.com`, authorization code flow, and `openid profile email` scopes. The Google preset explicitly uses Google's stable `sub` claim as the provider key because the preset maps to Google's fixed issuer. Email claims are copied when present but are not used as the provider key.

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

Configures provider name `Apple`, authority `https://appleid.apple.com`, authorization code flow, `form_post` response mode, and `openid email name` scopes. Apple does not publish a user-info endpoint, so the preset reads identity claims from the validated ID token and maps first-authorization display name hints from Apple's `user` authorization response parameter when present. The Apple preset explicitly uses Apple's stable `sub` claim as the provider key because the preset maps to Apple's fixed issuer. Apple client secrets are normally application-generated JWTs; production apps must configure generation, rotation, and storage themselves through `OpenIdConnectOptions`, for example by setting `ClientSecret` in the configure callback.

Apple profile claims are display hints only. The `name` value may only be returned during the first authorization, and `email` may be an Apple private relay address. Invitation email matching uses the generic verified-email policy unless the application replaces `IOidcInvitationEmailMatchPolicy`.

Microsoft Entra ID:

```csharp
using Ashlar.OAuth.Providers.Microsoft;

options.AddMicrosoft("contoso.onmicrosoft.com", ...);
```

Builds authority `https://login.microsoftonline.com/{tenant}/v2.0`. The tenant segment is explicit and should match the application's intended sign-in audience. Invitation registration uses the standard verified `email` policy by default, which means Microsoft principals usually need an application-provided or token-provided standard `email_verified` signal to pass. Microsoft email-like claims such as `preferred_username`, `upn`, and `unique_name` are not trusted for invitation matching unless explicitly allowed for the tenant.

The explicit-tenant Microsoft preset uses bare `sub` provider keys because a single configured provider name maps to one Microsoft tenant issuer. Use separate provider names for separate tenants.

```csharp
options.AddMicrosoft(
    "contoso.onmicrosoft.com",
    configureInvitationEmailMatch: match =>
    {
        match.AllowedEmailLikeClaimTypes.Add("upn");
    });
```

Only allow Microsoft email-like claims when tenant policy makes the selected claim authoritative for the invited mailbox. Microsoft documents these claims as mutable, display-oriented, or affected by alternate-login and guest-user behavior; this opt-in does not prove general mailbox control.

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
/signin-oauth/{scheme}
```

For example, register `https://localhost:5001/signin-oidc/Google` with Google for local development.
For GitHub, register `https://localhost:5001/signin-oauth/GitHub`.

The temporary external OAuth/OIDC cookie that carries callback tickets is secure-only. Real provider callbacks, including local development callbacks, should use HTTPS URLs like the examples above.

Start an external OIDC challenge with the provider scheme:

```csharp
await httpContext.ChallengeAsync("Google", new AuthenticationProperties
{
    RedirectUri = "/signin/google/callback"
});
```

Account linking must use properties bound to the current Ashlar user and session; an ordinary sign-in ticket is intentionally rejected:

```csharp
var properties = AshlarExternalAccountLinkService.CreateExternalLinkChallengeProperties(
    currentUserId,
    currentSessionId,
    "/account/external/google/link/callback");
await httpContext.ChallengeAsync("Google", properties);
```

For MFA-aware applications, complete the callback only to an Ashlar assertion, pass that assertion through `IAuthenticationOrchestrator`, and issue the Ashlar session only after orchestration succeeds:

```csharp
var assertionResult = await externalCredentials.CompleteExternalAssertionAsync(httpContext, "Google");
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

await signInManager.SignInAsync(
    httpContext,
    authentication,
    httpContext.ToSessionRequest(authentication.User, new AuthenticationProviderKey(ProviderType.Oidc, "Google")),
    cancellationToken);
return Results.Redirect("/");
```

`CompleteExternalAssertionAsync` validates the temporary external ticket, checks that it was issued for the expected configured provider and provider kind, clears the external cookie, and returns a mapped `ExternalIdentityAssertion`. Use this method for both OIDC and non-OIDC OAuth2 providers. The external ticket must include Ashlar's provider name, scheme name, and provider type metadata; missing or mismatched metadata is rejected as a provider mismatch. A successful assertion result means the external credential was validated and mapped; it does not mean an application session may be issued.

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
- ASP.NET Core's OAuth handler performs OAuth state validation and code exchange for GitHub, including S256 PKCE by default. GitHub identity is then loaded from GitHub's user-info API and mapped to `ProviderType.OAuth`.
- Generic OIDC providers use issuer-qualified provider keys derived from validated `iss` and `sub` claims by default. Fixed single-issuer presets can explicitly use bare `sub`. Ashlar never uses email as an OIDC provider key.
- Ashlar uses GitHub `/user` `id` as the stable OAuth provider key, not email, username, login, or display name.
- Google `hd` is an organization/domain signal, not an Ashlar tenant. When domains are passed to `AddGoogle`, Ashlar.OAuth validates the returned `hd` claim before external credential authentication completes.

## Invitation registration

`AshlarOidcInvitationRegistrationService` accepts an existing Ashlar invitation token with a validated OIDC identity and then links the OIDC credential to the accepted Ashlar user. It does not sign the user in automatically. Use the `HttpContext` completion API so Ashlar reads and clears the ASP.NET Core temporary external ticket itself; account-changing OAuth/OIDC APIs do not accept raw `ClaimsPrincipal` or raw `AuthenticateResult` values from application code.

By default, `StandardOidcVerifiedEmailMatchPolicy` requires generic OIDC providers to match a standard `email` claim with `email_verified=true` before the invitation is consumed. Microsoft tenant providers registered with `AddMicrosoft` use the same verified `email` requirement by default. Microsoft's ID-token claim reference does not document a standard `email_verified` claim, and its `email`, `preferred_username`, `upn`, and `unique_name` claims can be mutable, display-oriented, aliases, guest-user identifiers, or tenant-specific usernames rather than mailbox-control proof.

Deployments that understand their Microsoft tenant claim semantics can explicitly allow selected email-like claim types:

```csharp
options.AddMicrosoft(
    "contoso.onmicrosoft.com",
    configureInvitationEmailMatch: match =>
    {
        match.AllowedEmailLikeClaimTypes.Add("upn");
    });
```

This opt-in is tenant-policy-specific and is not general mailbox verification. `AddMicrosoft` requires a tenant-specific authority and rejects `common`, `organizations`, and `consumers`; use separate provider names for separate tenants. `AddMicrosoftPersonalAccounts` and `AddMicrosoftAnyAccount` are sign-in/linking presets and do not opt into Microsoft invitation email-like claim matching. Applications with stricter requirements can replace `IOidcInvitationEmailMatchPolicy`. Missing email, unverified email, mismatched email, invalid tokens, provider mismatch, and link failures are returned as explicit statuses for application branching. Public UI should still use generic failure messages.

GitHub invitation registration is not supported by `AshlarOidcInvitationRegistrationService`. GitHub's basic `/user` endpoint does not provide a reliable verified-email policy, and this package does not call GitHub's email API in this slice. Applications that need GitHub invitation registration should first define and implement an explicit verified-email policy.

- `AuthenticationContext.TenantId` remains Ashlar's tenant context and should be supplied by the app when completing tenant-aware sign-in or invitation registration flows. Invitation registration rejects a context tenant that does not match the invitation tenant.
- Do not log or persist authorization codes, access tokens, refresh tokens, ID tokens, raw claim payloads, or cookies in this slice.
