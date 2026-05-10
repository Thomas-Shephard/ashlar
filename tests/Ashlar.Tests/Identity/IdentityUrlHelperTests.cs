using Ashlar.Identity;

namespace Ashlar.Tests.Identity;

public class IdentityUrlHelperTests
{
    [Test]
    public void ConstructCallbackUrlThrowsArgumentExceptionWhenBaseUriIsNotAbsolute()
    {
        var baseUri = new Uri("/relative/path", UriKind.Relative);
        var userId = Guid.NewGuid();

        var ex = Assert.Throws<ArgumentException>(() => IdentityUrlHelper.ConstructCallbackUrl(baseUri, userId, "token123", "t", "u"));
        Assert.That(ex.Message, Does.Contain("Callback base URI must be an absolute URI."));
    }

    [Test]
    public void FormatEmailBodyAppendsCallbackUrlWhenTemplateDoesNotContainPlaceholder()
    {
        const string template = "Click this link:";
        const string callbackUrl = "http://localhost/confirm?t=123&u=456";

        var result = IdentityUrlHelper.FormatEmailBody(template, callbackUrl, "Fallback", "token123");

        Assert.That(result, Is.EqualTo("Click this link: http://localhost/confirm?t=123&u=456"));
    }
}
