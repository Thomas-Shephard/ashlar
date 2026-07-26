namespace Ashlar.Tests.Identity.Features.Authentication;

internal sealed class AuthenticationClaimsTests
{
    [Test]
    public void FromSingleValuesShouldCreateMultiValueClaims()
    {
        var claims = AuthenticationClaims.FromSingleValues(new Dictionary<string, string> { ["role"] = "admin,editor" });

        Assert.That(claims["role"], Is.EqualTo(["admin,editor"]));
    }

    [Test]
    public void FromSingleValuesShouldReturnEmptyClaimsForNull()
    {
        var claims = AuthenticationClaims.FromSingleValues(null);

        Assert.That(claims, Is.Empty);
    }

    [Test]
    public void CopyShouldCreateReadOnlyClaimValueCopies()
    {
        var values = new List<string> { "admin" };
        var claims = AuthenticationClaims.Copy(new Dictionary<string, IReadOnlyList<string>> { ["role"] = values });

        values[0] = "editor";

        using (Assert.EnterMultipleScope())
        {
            Assert.That(claims["role"], Is.EqualTo(["admin"]));
            Assert.Throws<NotSupportedException>(() => ((IDictionary<string, IReadOnlyList<string>>)claims).Add("new", ["value"]));
        }
    }

    [Test]
    public void CopyShouldReturnEmptyClaimsForNull()
    {
        var claims = AuthenticationClaims.Copy(null);

        Assert.That(claims, Is.Empty);
    }

    [Test]
    public void FirstValueOrDefaultShouldReturnFirstClaimValue()
    {
        var claims = new Dictionary<string, IReadOnlyList<string>> { ["role"] = ["admin", "editor"], ["empty"] = [] };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AuthenticationClaims.FirstValueOrDefault(claims, "role"), Is.EqualTo("admin"));
            Assert.That(AuthenticationClaims.FirstValueOrDefault(claims, "empty"), Is.Null);
            Assert.That(AuthenticationClaims.FirstValueOrDefault(claims, "missing"), Is.Null);
            Assert.That(AuthenticationClaims.FirstValueOrDefault(null, "role"), Is.Null);
        }
    }
}
