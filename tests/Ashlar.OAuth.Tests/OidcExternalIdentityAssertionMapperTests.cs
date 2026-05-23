using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ashlar.OAuth.Tests;

internal sealed class OidcExternalIdentityAssertionMapperTests
{
    [Test]
    public void MapShouldUseSubjectAsProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("sub", "subject-123"),
            new Claim("email", "person@example.com"),
            new Claim("name", "Person")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map(" Google ", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(assertion.ProviderKey, Is.EqualTo("subject-123"));
            Assert.That(assertion.Claims["email"], Is.EqualTo(["person@example.com"]));
            Assert.That(assertion.Claims["name"], Is.EqualTo(["Person"]));
        }
    }

    [Test]
    public void MapShouldNotUseEmailAsProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("sub", "stable-subject"),
            new Claim("email", "person@example.com")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        Assert.That(assertion.ProviderKey, Is.EqualTo("stable-subject"));
    }

    [Test]
    public void MapShouldUseIssuerAndSubjectProviderKeyMode()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://login.example/tenant"),
            new Claim("sub", "stable-subject")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("MicrosoftAny", principal, AshlarOidcProviderKeyMode.IssuerAndSubject);

        Assert.That(assertion.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://login.example/tenant", "stable-subject")));
    }

    [Test]
    public void MapShouldUseBoundedIssuerAndSubjectProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("iss", "https://login.example/tenant"),
            new Claim("sub", new string('s', 2048))
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("MicrosoftAny", principal, AshlarOidcProviderKeyMode.IssuerAndSubject);

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
            ]),
            AshlarOidcProviderKeyMode.IssuerAndSubject);
        var second = OidcExternalIdentityAssertionMapper.Map(
            "MicrosoftAny",
            CreatePrincipal(
            [
                new Claim("iss", "https://login.example/tenant"),
                new Claim("sub", "a|b")
            ]),
            AshlarOidcProviderKeyMode.IssuerAndSubject);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.ProviderKey, Is.Not.EqualTo(second.ProviderKey));
            Assert.That(first.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://login.example/tenant|a", "b")));
            Assert.That(second.ProviderKey, Is.EqualTo(CreateExpectedIssuerSubjectKey("https://login.example/tenant", "a|b")));
        }
    }

    [Test]
    public void MapShouldRejectIssuerAndSubjectProviderKeyModeWhenIssuerIsMissing()
    {
        var principal = CreatePrincipal([new Claim("sub", "stable-subject")]);

        Assert.Throws<InvalidOperationException>(() => OidcExternalIdentityAssertionMapper.Map("MicrosoftAny", principal, AshlarOidcProviderKeyMode.IssuerAndSubject));
    }

    [Test]
    public void MapShouldRejectUnsupportedProviderKeyMode()
    {
        var principal = CreatePrincipal([new Claim("sub", "stable-subject")]);

        Assert.Throws<InvalidOperationException>(() => OidcExternalIdentityAssertionMapper.Map("MicrosoftAny", principal, (AshlarOidcProviderKeyMode)99));
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
    public void MapShouldPreserveDuplicateClaimTypes()
    {
        var principal = CreatePrincipal(
        [
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
