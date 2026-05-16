using Ashlar.Identity;

namespace Ashlar.Tests.Identity;

internal sealed class IdentityUrlHelperTests
{
    [Test]
    public void ConstructCallbackUrlThrowsArgumentExceptionWhenBaseUriIsNotAbsolute()
    {
        var baseUri = new Uri("/relative/path", UriKind.Relative);
        var userId = Guid.NewGuid();

        var ex = Assert.Throws<ArgumentException>(() => IdentityUrlHelper.ConstructCallbackUrl(baseUri, "t", "token123", userId, "u"));
        Assert.That(ex.Message, Does.Contain("Callback base URI must be an absolute URI."));
    }

    [Test]
    public void ConstructCallbackUrlReturnsNullWhenBaseUriIsNull()
    {
        var result = IdentityUrlHelper.ConstructCallbackUrl(null, "t", "token123");
        Assert.That(result, Is.Null);
    }

    [Test]
    public void FormatEmailBodyReturnsEmptyStringWhenTemplateIsNull()
    {
        var result = IdentityUrlHelper.FormatEmailBody(null, "https://example.com");
        Assert.That(result, Is.EqualTo(string.Empty));
    }

    [Test]
    public void FormatEmailBodyUsesPlaceholderWhenPresent()
    {
        var result = IdentityUrlHelper.FormatEmailBody("Link: {0}", "https://example.com");
        Assert.That(result, Is.EqualTo("Link: https://example.com"));
    }

    [Test]
    public void FormatEmailBodyAppendsCallbackUrlWhenTemplateDoesNotContainPlaceholder()
    {
        const string template = "Click this link:";
        const string callbackUrl = "http://localhost/confirm?t=123&u=456";

        var result = IdentityUrlHelper.FormatEmailBody(template, callbackUrl, "Fallback", "token123");

        Assert.That(result, Is.EqualTo("Click this link: http://localhost/confirm?t=123&u=456"));
    }

    [Test]
    public void FormatEmailBodyUsesFallbackWhenCallbackUrlIsNull()
    {
        var result = IdentityUrlHelper.FormatEmailBody("Template", null, "Label", "token");
        Assert.That(result, Is.EqualTo("Label: token"));
    }

    [Test]
    public void FormatEmailBodyReturnsTemplateWhenCallbackAndFallbackAreMissing()
    {
        var result = IdentityUrlHelper.FormatEmailBody("Template", null);
        Assert.That(result, Is.EqualTo("Template"));

        result = IdentityUrlHelper.FormatEmailBody("Template", null, "Label");
        Assert.That(result, Is.EqualTo("Template"));

        result = IdentityUrlHelper.FormatEmailBody("Template", null, null, "token");
        Assert.That(result, Is.EqualTo("Template"));
    }
}
