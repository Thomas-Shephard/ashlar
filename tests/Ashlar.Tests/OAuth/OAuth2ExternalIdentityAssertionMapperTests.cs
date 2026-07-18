using System.Security.Claims;

namespace Ashlar.Tests.OAuth;

internal sealed class OAuth2ExternalIdentityAssertionMapperTests
{
    [Test]
    public void MapShouldUseStableIdAsProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("id", "12345"),
            new Claim("login", "octocat"),
            new Claim("name", "The Octocat"),
            new Claim("email", "octo@example.com")
        ]);

        var assertion = OAuth2ExternalIdentityAssertionMapper.Map(" GitHub ", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.ProviderIdentity, Is.EqualTo(new AuthenticationProviderKey(ProviderType.OAuth, "GitHub")));
            Assert.That(assertion.ProviderKey, Is.EqualTo("12345"));
            Assert.That(assertion.Claims["login"], Is.EqualTo(["octocat"]));
            Assert.That(assertion.Claims["name"], Is.EqualTo(["The Octocat"]));
            Assert.That(assertion.Claims["email"], Is.EqualTo(["octo@example.com"]));
        }
    }

    [Test]
    public void MapShouldNotUseLoginNameOrEmailAsProviderKey()
    {
        var principal = CreatePrincipal(
        [
            new Claim("id", "12345"),
            new Claim("login", "octocat"),
            new Claim("name", "The Octocat"),
            new Claim("email", "octo@example.com")
        ]);

        var assertion = OAuth2ExternalIdentityAssertionMapper.Map("GitHub", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.ProviderKey, Is.EqualTo("12345"));
            Assert.That(assertion.ProviderKey, Is.Not.EqualTo("octocat"));
            Assert.That(assertion.ProviderKey, Is.Not.EqualTo("The Octocat"));
            Assert.That(assertion.ProviderKey, Is.Not.EqualTo("octo@example.com"));
        }
    }

    [Test]
    public void MapShouldRejectMissingId()
    {
        var principal = CreatePrincipal(
        [
            new Claim("login", "octocat"),
            new Claim("email", "octo@example.com")
        ]);

        Assert.Throws<InvalidOperationException>(() => OAuth2ExternalIdentityAssertionMapper.Map("GitHub", principal));
    }

    [Test]
    public void MapShouldRejectUnsafeProviderKeyClaimType()
    {
        var principal = CreatePrincipal(
        [
            new Claim("email", "octo@example.com")
        ]);

        var exception = Assert.Throws<ArgumentException>(() => OAuth2ExternalIdentityAssertionMapper.Map("GitHub", principal, " email "));

        Assert.That(exception?.Message, Does.Contain("stable immutable provider user id"));
    }

    [Test]
    public void MapShouldAllowExplicitUnsafeProviderKeyClaimType()
    {
        var principal = CreatePrincipal(
        [
            new Claim("email", "stable-provider-id")
        ]);

        var assertion = OAuth2ExternalIdentityAssertionMapper.Map(
            "CustomOAuth",
            principal,
            " email ",
            allowUnsafeProviderKeyClaimType: true);

        Assert.That(assertion.ProviderKey, Is.EqualTo("stable-provider-id"));
    }

    [Test]
    public void MapShouldSkipSensitiveClaims()
    {
        var principal = CreatePrincipal(
        [
            new Claim("id", "12345"),
            new Claim("access_token", "secret"),
            new Claim("refresh_token", "secret"),
            new Claim("id_token", "secret"),
            new Claim("authorization_code", "secret"),
            new Claim("code", "secret"),
            new Claim("cookie", "secret"),
            new Claim("client_secret", "secret"),
            new Claim("password", "secret")
        ]);

        var assertion = OAuth2ExternalIdentityAssertionMapper.Map("GitHub", principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(assertion.Claims, Does.ContainKey("id"));
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
            new Claim("id", "12345"),
            new Claim("role", "admin"),
            new Claim("role", "editor")
        ]);

        var assertion = OAuth2ExternalIdentityAssertionMapper.Map("GitHub", principal);

        Assert.That(assertion.Claims["role"], Is.EqualTo(["admin", "editor"]));
    }

    private static ClaimsPrincipal CreatePrincipal(IEnumerable<Claim> claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "oauth"));
    }
}
