using System.Security.Claims;

namespace Ashlar.OAuth.Tests;

internal sealed class AshlarOidcProfileMapperTests
{
    [Test]
    public void MapShouldUseTrimmedNameAsDisplayName()
    {
        var principal = CreatePrincipal(
            new Claim("name", "  Ada Lovelace  "),
            new Claim("given_name", "  Ada  "),
            new Claim("family_name", "  Lovelace  "),
            new Claim("email", "  ada@example.com  "),
            new Claim("email_verified", "true"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("Ada Lovelace"));
            Assert.That(profile.GivenName, Is.EqualTo("Ada"));
            Assert.That(profile.FamilyName, Is.EqualTo("Lovelace"));
            Assert.That(profile.Email, Is.EqualTo("ada@example.com"));
            Assert.That(profile.EmailVerified, Is.True);
        }
    }

    [Test]
    public void MapShouldUseGivenAndFamilyNameAsDisplayNameFallback()
    {
        var principal = CreatePrincipal(
            new Claim("given_name", "  Grace  "),
            new Claim("family_name", "  Hopper  "));

        var profile = AshlarOidcProfileMapper.Map(principal);

        Assert.That(profile.DisplayName, Is.EqualTo("Grace Hopper"));
    }

    [Test]
    public void MapShouldUseOnlyGivenNameAsDisplayNameFallback()
    {
        var principal = CreatePrincipal(new Claim("given_name", "  Grace  "));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("Grace"));
            Assert.That(profile.FamilyName, Is.Null);
        }
    }

    [Test]
    public void MapShouldUseOnlyFamilyNameAsDisplayNameFallback()
    {
        var principal = CreatePrincipal(new Claim("family_name", "  Hopper  "));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("Hopper"));
            Assert.That(profile.GivenName, Is.Null);
        }
    }

    [Test]
    public void MapShouldReturnNullValuesWhenClaimsAreMissing()
    {
        var profile = AshlarOidcProfileMapper.Map(CreatePrincipal());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.Null);
            Assert.That(profile.GivenName, Is.Null);
            Assert.That(profile.FamilyName, Is.Null);
            Assert.That(profile.Email, Is.Null);
            Assert.That(profile.EmailVerified, Is.Null);
        }
    }

    [Test]
    public void MapShouldNotRequireSubjectClaim()
    {
        var principal = CreatePrincipal(
            new Claim("name", "  Google User  "),
            new Claim("email", "user@gmail.example"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        Assert.That(profile.DisplayName, Is.EqualTo("Google User"));
    }

    [Test]
    public void MapShouldUseFirstNonEmptyTrimmedClaimValue()
    {
        var principal = CreatePrincipal(
            new Claim("unrelated", "ignored"),
            new Claim("name", " "),
            new Claim("name", "  First Name  "),
            new Claim("name", "Second Name"),
            new Claim("given_name", ""),
            new Claim("given_name", "  FirstGiven  "),
            new Claim("family_name", " "),
            new Claim("family_name", "  FirstFamily  "),
            new Claim("email", ""),
            new Claim("email", "  first@example.com  "),
            new Claim("email", "second@example.com"),
            new Claim("email_verified", ""),
            new Claim("email_verified", "  1  "),
            new Claim("email_verified", "false"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("First Name"));
            Assert.That(profile.GivenName, Is.EqualTo("FirstGiven"));
            Assert.That(profile.FamilyName, Is.EqualTo("FirstFamily"));
            Assert.That(profile.Email, Is.EqualTo("first@example.com"));
            Assert.That(profile.EmailVerified, Is.True);
        }
    }

    [TestCase("true", true)]
    [TestCase("True", true)]
    [TestCase("1", true)]
    [TestCase("false", false)]
    [TestCase("False", false)]
    [TestCase("0", false)]
    public void MapShouldParseRecognizedEmailVerifiedValues(string value, bool expected)
    {
        var profile = AshlarOidcProfileMapper.Map(CreatePrincipal(new Claim("email_verified", value)));

        Assert.That(profile.EmailVerified, Is.EqualTo(expected));
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("yes")]
    [TestCase("TRUE")]
    public void MapShouldReturnNullForBlankOrUnrecognizedEmailVerifiedValues(string value)
    {
        var profile = AshlarOidcProfileMapper.Map(CreatePrincipal(new Claim("email_verified", value)));

        Assert.That(profile.EmailVerified, Is.Null);
    }

    [Test]
    public void MapShouldReturnNullForMissingEmailVerifiedValue()
    {
        var profile = AshlarOidcProfileMapper.Map(CreatePrincipal(new Claim("email", "person@example.com")));

        Assert.That(profile.EmailVerified, Is.Null);
    }

    [Test]
    public void MapShouldSupportGoogleStyleProfileClaims()
    {
        var principal = CreatePrincipal(
            new Claim("sub", "google-subject"),
            new Claim("name", "Google Person"),
            new Claim("given_name", "Google"),
            new Claim("family_name", "Person"),
            new Claim("email", "person@gmail.example"),
            new Claim("email_verified", "true"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("Google Person"));
            Assert.That(profile.GivenName, Is.EqualTo("Google"));
            Assert.That(profile.FamilyName, Is.EqualTo("Person"));
            Assert.That(profile.Email, Is.EqualTo("person@gmail.example"));
            Assert.That(profile.EmailVerified, Is.True);
        }
    }

    [Test]
    public void MapShouldSupportMicrosoftStyleStandardOidcProfileClaims()
    {
        var principal = CreatePrincipal(
            new Claim("sub", "microsoft-subject"),
            new Claim("name", "Microsoft Person"),
            new Claim("given_name", "Microsoft"),
            new Claim("family_name", "Person"),
            new Claim("email", "person@contoso.example"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("Microsoft Person"));
            Assert.That(profile.GivenName, Is.EqualTo("Microsoft"));
            Assert.That(profile.FamilyName, Is.EqualTo("Person"));
            Assert.That(profile.Email, Is.EqualTo("person@contoso.example"));
            Assert.That(profile.EmailVerified, Is.Null);
        }
    }

    [Test]
    public void MapShouldSupportAspNetCoreMappedClaimTypes()
    {
        var principal = CreatePrincipal(
            new Claim(ClaimTypes.Name, "  Mapped Person  "),
            new Claim(ClaimTypes.GivenName, "  Mapped  "),
            new Claim(ClaimTypes.Surname, "  Person  "),
            new Claim(ClaimTypes.Email, "  mapped@example.com  "),
            new Claim("email_verified", "False"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("Mapped Person"));
            Assert.That(profile.GivenName, Is.EqualTo("Mapped"));
            Assert.That(profile.FamilyName, Is.EqualTo("Person"));
            Assert.That(profile.Email, Is.EqualTo("mapped@example.com"));
            Assert.That(profile.EmailVerified, Is.False);
        }
    }

    [Test]
    public void MapShouldUseFirstNonEmptyAcrossOidcAndMappedClaimTypes()
    {
        var principal = CreatePrincipal(
            new Claim(ClaimTypes.Name, " "),
            new Claim("name", "  OIDC Name  "),
            new Claim(ClaimTypes.GivenName, ""),
            new Claim("given_name", "  OIDC Given  "),
            new Claim(ClaimTypes.Surname, " "),
            new Claim("family_name", "  OIDC Family  "),
            new Claim(ClaimTypes.Email, ""),
            new Claim("email", "  oidc@example.com  "));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.EqualTo("OIDC Name"));
            Assert.That(profile.GivenName, Is.EqualTo("OIDC Given"));
            Assert.That(profile.FamilyName, Is.EqualTo("OIDC Family"));
            Assert.That(profile.Email, Is.EqualTo("oidc@example.com"));
        }
    }

    [Test]
    public void MapShouldNotUseEmailLikeClaimsAsDisplayNameFallbacks()
    {
        var principal = CreatePrincipal(
            new Claim("preferred_username", "preferred@example.com"),
            new Claim("upn", "upn@example.com"),
            new Claim("unique_name", "unique@example.com"),
            new Claim("email", "email@example.com"));

        var profile = AshlarOidcProfileMapper.Map(principal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.DisplayName, Is.Null);
            Assert.That(profile.Email, Is.EqualTo("email@example.com"));
        }
    }

    [Test]
    public void GetSuggestedDisplayNameShouldReturnMappedDisplayName()
    {
        var displayName = AshlarOidcProfileMapper.GetSuggestedDisplayName(CreatePrincipal(new Claim("given_name", "Ada")));

        Assert.That(displayName, Is.EqualTo("Ada"));
    }

    [Test]
    public void MapShouldRejectNullPrincipal()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarOidcProfileMapper.Map(null!));
            Assert.Throws<ArgumentNullException>(() => AshlarOidcProfileMapper.GetSuggestedDisplayName(null!));
        }
    }

    private static ClaimsPrincipal CreatePrincipal(params Claim[] claims)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "oidc"));
    }
}
