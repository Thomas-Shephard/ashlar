using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Ashlar.OAuth.Providers.Apple;

namespace Ashlar.Tests.OAuth;

internal sealed class OidcExternalIdentityAssertionMapperTests
{
    [Test]
    public void MapShouldUseIssuerAndSubjectAsProviderKeyByDefault()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://accounts.example.com"),
            new Claim("sub", "subject-123"),
            new Claim("email", "person@example.com"),
            new Claim("name", "Person")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map(" Google ", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(assertion.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://accounts.example.com", "subject-123")));
            Assert.That(assertion.Claims["email"], Is.EqualTo(["person@example.com"]));
            Assert.That(assertion.Claims["name"], Is.EqualTo(["Person"]));
        }
    }

    [Test]
    public void MapShouldNotUseEmailAsProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://accounts.example.com"),
            new Claim("sub", "stable-subject"),
            new Claim("email", "person@example.com")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        Assert.That(assertion.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://accounts.example.com", "stable-subject")));
    }

    [Test]
    public void MapShouldUseAppleIssuerAndSubjectAsProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", AppleOidcDefaults.Authority),
            new Claim("sub", "apple-subject"),
            new Claim("email", "person@privaterelay.appleid.com")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map(AppleOidcDefaults.ProviderName, principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Apple")));
            Assert.That(assertion.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey(AppleOidcDefaults.Authority, "apple-subject")));
            Assert.That(assertion.Claims["iss"], Is.EqualTo([AppleOidcDefaults.Authority]));
            Assert.That(assertion.Claims["email"], Is.EqualTo(["person@privaterelay.appleid.com"]));
        }
    }

    [Test]
    public void MapShouldCreateDifferentIssuerAndSubjectProviderKeysForDifferentIssuers()
    {
        var first = OidcExternalIdentityAssertionMapper.Map(
            "SharedOidc",
            CreatePrincipal(
            [
                new Claim("iss", "https://issuer-one.example"),
                new Claim("sub", "same-subject")
            ]));
        var second = OidcExternalIdentityAssertionMapper.Map(
            "SharedOidc",
            CreatePrincipal(
            [
                new Claim("iss", "https://issuer-two.example"),
                new Claim("sub", "same-subject")
            ]));

        Assert.That(first.ProviderKey, Is.Not.EqualTo(second.ProviderKey));
    }

    [Test]
    public void MapShouldNotExposeInternalValidatedIssuerClaim()
    {
        var principal = CreatePrincipal(
        [
            new Claim("sub", "subject-123"),
            new Claim(AshlarOAuthAuthenticationProperties.OidcIssuerClaim, "https://accounts.example.com")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        Assert.That(assertion.Claims, Does.Not.ContainKey(AshlarOAuthAuthenticationProperties.OidcIssuerClaim));
    }

    [Test]
    public void MapShouldPreserveOpaqueSubjectWhitespace()
    {
        var first = OidcExternalIdentityAssertionMapper.Map("SharedOidc", CreatePrincipal([new Claim("iss", "https://issuer.example"), new Claim("sub", "subject")]));
        var second = OidcExternalIdentityAssertionMapper.Map("SharedOidc", CreatePrincipal([new Claim("iss", "https://issuer.example"), new Claim("sub", " subject ")]));

        Assert.That(first.ProviderKey, Is.Not.EqualTo(second.ProviderKey));
    }

    [Test]
    public void MapShouldUseBoundedIssuerAndSubjectProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://login.example/tenant"),
            new Claim("sub", new string('s', 2048))
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("MicrosoftAny", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.ProviderKey, Does.StartWith("oidc-sha256:"));
            Assert.That(assertion.ProviderKey, Has.Length.EqualTo(76));
        }
    }

    [Test]
    public void MapShouldCreateCollisionResistantIssuerAndSubjectProviderKey()
    {
        var first = OidcExternalIdentityAssertionMapper.Map(
            "MicrosoftAny",
            CreatePrincipal(
            [
                new Claim("iss", "https://login.example/tenant|a"),
                new Claim("sub", "b")
            ]));
        var second = OidcExternalIdentityAssertionMapper.Map(
            "MicrosoftAny",
            CreatePrincipal(
            [
                new Claim("iss", "https://login.example/tenant"),
                new Claim("sub", "a|b")
            ]));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ProviderKey, Is.Not.EqualTo(second.ProviderKey));
            Assert.That(first.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://login.example/tenant|a", "b")));
            Assert.That(second.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://login.example/tenant", "a|b")));
        }
    }

    [Test]
    public void MapShouldRejectWhenIssuerIsMissing()
    {
        var principal = CreatePrincipal([new Claim("sub", "stable-subject")]);

        var exception = Assert.Throws<InvalidOperationException>(() => OidcExternalIdentityAssertionMapper.Map("SharedOidc", principal));

        Assert.That(exception?.Message, Does.Contain("issuer claim"));
    }

    [TestCase("")]
    [TestCase(" ")]
    public void MapShouldRejectWhenIssuerIsBlank(string issuer)
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", issuer),
            new Claim("sub", "stable-subject")
        ]);

        var exception = Assert.Throws<InvalidOperationException>(() => OidcExternalIdentityAssertionMapper.Map("SharedOidc", principal));

        Assert.That(exception?.Message, Does.Contain("issuer claim"));
    }

    [Test]
    public void MapShouldRejectMissingSubject()
    {
        var principal = CreatePrincipal([new Claim("email", "person@example.com")]);

        Assert.Throws<InvalidOperationException>(() => OidcExternalIdentityAssertionMapper.Map("Google", principal));
    }

    [Test]
    public void MapShouldRejectMissingProviderName()
    {
        var principal = CreatePrincipal([new Claim("sub", "subject")]);

        Assert.Throws<ArgumentException>(() => OidcExternalIdentityAssertionMapper.Map(" ", principal));
    }

    [Test]
    public void MapShouldSkipMalformedOrEmptyClaims()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://accounts.example.com"),
            new Claim("sub", "subject"),
            new Claim("empty-value", ""),
            new Claim("", "value")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.Claims, Does.ContainKey("sub"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("empty-value"));
            Assert.That(assertion.Claims, Does.Not.ContainKey(""));
        }
    }

    [Test]
    public void MapShouldSkipSensitiveClaims()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://accounts.example.com"),
            new Claim("sub", "subject"),
            new Claim("access_token", "secret"),
            new Claim("refresh_token", "secret"),
            new Claim("id_token", "secret"),
            new Claim("authorization_code", "secret"),
            new Claim("code", "secret"),
            new Claim("cookie", "secret"),
            new Claim("client_secret", "secret"),
            new Claim("password", "secret")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.Claims, Does.ContainKey("sub"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("access_token"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("refresh_token"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("id_token"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("authorization_code"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("code"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("cookie"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("client_secret"));
            Assert.That(assertion.Claims, Does.Not.ContainKey("password"));
        }
    }

    [Test]
    public void MapShouldPreserveDuplicateClaimTypes()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://accounts.example.com"),
            new Claim("sub", "subject"),
            new Claim("role", "admin,editor"),
            new Claim("role", "editor")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        Assert.That(assertion.Claims["role"], Is.EqualTo(["admin,editor", "editor"]));
    }

    private static ClaimsPrincipal CreatePrincipal(IEnumerable<Claim> claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc"));
    }

    private static string CreateExpectedIssuerSubjectKey(string issuer, string subject)
    {
        var payload = JsonSerializer.Serialize(new IssuerSubjectProviderKey(issuer, subject));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return string.Concat("oidc-sha256:", Convert.ToHexString(hash));
    }

    private sealed record IssuerSubjectProviderKey(string Issuer, string Subject);
}
