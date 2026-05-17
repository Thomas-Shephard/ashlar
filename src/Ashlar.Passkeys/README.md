# Ashlar.Passkeys

`Ashlar.Passkeys` adds first-party passkey/WebAuthn/FIDO2 orchestration for Ashlar without adding WebAuthn dependencies to the core `Ashlar` package.

Register the package with:

```csharp
services.AddAshlarIdentity();
services.AddAshlarPostgres(connectionString);
services.AddAshlarPasskeys(options =>
{
    options.RelyingPartyId = "example.com";
    options.RelyingPartyName = "Example";
    options.Origin = "https://example.com";
});
```

Applications may replace the default `IPasskeyCeremonyValidator` adapter backed by `Fido2NetLib`. For .NET 8+, the NuGet package is `Fido2`; Ashlar keeps that dependency in this optional package so core consumers that do not use passkeys do not reference it.

`AddAshlarPasskeys()` also registers Ashlar MFA orchestration because passkeys can be used as MFA factors. Consumers must provide the usual identity and credential repositories plus `IPasskeyChallengeRepository` and `IAuthenticationHandshakeRepository`; `AddAshlarPostgres()` supplies these persistence services.

The service supports starting and completing registration, starting and completing authentication, listing passkeys, renaming display names, and revoking credentials. Registered passkeys are stored as normal Ashlar credentials with `ProviderType.Passkey`; public key and signature counter state live in structured credential metadata. Challenges are random, short-lived, purpose-scoped, origin/RP-scoped, and consumed atomically.

In account security posture, passkeys are shown separately from generic MFA. A registered passkey is a primary sign-in method and can also be an additional verification factor when an MFA or step-up policy accepts the `passkey` factor. Applications should not display "2FA enabled" merely because a user has a passkey; render the posture model's `PrimaryCredentials`, `AdditionalVerificationFactors`, and `Policy` fields instead.

Browser validation requires HTTPS in production, an RP ID that matches the browser origin host or one of its parent domains, is not a public suffix, and consistent `Origin` configuration. Loopback and `localhost` HTTP origins are allowed for local development where browsers treat them as secure contexts. The sample app can exercise the server endpoints, but full WebAuthn validation must be completed manually in a real browser with platform passkeys or a security key.
