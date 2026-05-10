using Ashlar.Identity;
using Ashlar.Identity.Models;
using Microsoft.Extensions.Options;

namespace Ashlar.Tests.Identity;

[TestFixture]
public class UriValidatorTests
{
    [Test]
    public void ConstructorThrowsWhenConfiguredUriIsNotAbsolute()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("relative/path");

        var ex = Assert.Throws<InvalidOperationException>(() => _ = new UriValidator(Options.Create(options)));
        Assert.That(ex.Message, Does.Contain("not a valid absolute URI"));
    }

    [Test]
    public void IsValidReturnsTrueForExactMatch()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app")), Is.True);
    }

    [Test]
    public void IsValidReturnsTrueForSubPath()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app/callback")), Is.True);
    }

    [Test]
    public void IsValidReturnsFalseForPrefixBypass()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/appEvil")), Is.False);
    }

    [Test]
    public void IsValidReturnsTrueForRootDomain()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/anything")), Is.True);
    }

    [Test]
    public void IsValidReturnsFalseForDifferentDomainPrefixBypass()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com.evil.com/")), Is.False);
    }

    [Test]
    public void IsValidRespectsAllowNullOption()
    {
        var options = new UriValidationOptions { AllowNull = true };
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(null), Is.True);

        options = new UriValidationOptions { AllowNull = false };
        validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(null), Is.False);
    }

    [Test]
    public void IsValidReturnsFalseForRelativeUri()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("/relative", UriKind.Relative)), Is.False);
    }

    [Test]
    public void IsValidReturnsTrueForLenientTrailingSlashMatch()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app/");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app")), Is.True);

        options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app/")), Is.True);
    }

    [Test]
    public void IsValidReturnsTrueForSubPathWithLenientBase()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app/");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app/callback")), Is.True);
    }

    [Test]
    public void ValidateOrThrowDoesNotThrowForValidUri()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.DoesNotThrow(() => validator.ValidateOrThrow(new Uri("https://example.com/app")));
    }

    [Test]
    public void ValidateOrThrowThrowsForInvalidUri()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.Throws<ArgumentException>(() => validator.ValidateOrThrow(new Uri("https://evil.com")));
    }
}
