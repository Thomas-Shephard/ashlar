using System.Security.Claims;

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
            Assert.That(assertion.Claims["email"], Is.EqualTo("person@example.com"));
            Assert.That(assertion.Claims["name"], Is.EqualTo("Person"));
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
    public void MapShouldAggregateDuplicateClaimTypes()
    {
        var principal = CreatePrincipal(
        [
            new Claim("sub", "subject"),
            new Claim("role", "admin"),
            new Claim("role", "editor")
        ]);

        var assertion = OidcExternalIdentityAssertionMapper.Map("Google", principal);

        Assert.That(assertion.Claims["role"], Is.EqualTo("admin,editor"));
    }

    private static ClaimsPrincipal CreatePrincipal(IEnumerable<Claim> claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc"));
    }
}
