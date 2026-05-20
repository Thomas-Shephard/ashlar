using Microsoft.Extensions.Options;

namespace Ashlar.Tests.Identity.Features.Services;

[TestFixture]
internal sealed class UriValidatorTests
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
    public void ConstructorThrowsWhenConfiguredUriUsesDangerousScheme()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("javascript:alert(1)");

        var ex = Assert.Throws<InvalidOperationException>(() => _ = new UriValidator(Options.Create(options)));
        Assert.That(ex.Message, Does.Contain("must use http or https"));
    }

    [Test]
    public void ConstructorThrowsWhenConfiguredUriContainsQueryOrFragment()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app?returnUrl=https://evil.com");

        Assert.Throws<InvalidOperationException>(() => _ = new UriValidator(Options.Create(options)));

        options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app#fragment");

        Assert.Throws<InvalidOperationException>(() => _ = new UriValidator(Options.Create(options)));
    }

    [Test]
    public void ConstructorThrowsWhenConfiguredUriContainsUserInfo()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://user:pass@example.com/app");

        Assert.Throws<InvalidOperationException>(() => _ = new UriValidator(Options.Create(options)));
    }

    [Test]
    public void ConstructorIgnoresBlankConfiguredUris()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add(" ");
        options.AllowedCallbackUris.Add("https://example.com/app");

        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app")), Is.True);
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

        using (Assert.EnterMultipleScope())
        {
            Assert.That(validator.IsValid(new Uri("https://example.com/appEvil")), Is.False);
            Assert.That(validator.IsValid(new Uri("https://example.com/app2")), Is.False);
        }
    }

    [Test]
    public void IsValidReturnsFalseForDifferentScheme()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("http://example.com/app")), Is.False);
    }

    [Test]
    public void IsValidReturnsFalseForDifferentHost()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://other.example.com/app")), Is.False);
    }

    [Test]
    public void IsValidReturnsFalseForDifferentPort()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com:8443/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/app")), Is.False);
    }

    [Test]
    public void IsValidReturnsFalseForDangerousOrUnexpectedScheme()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("ftp://example.com/app")), Is.False);
    }

    [Test]
    public void IsValidReturnsFalseForCandidateQueryOrFragment()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com/app");
        var validator = new UriValidator(Options.Create(options));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(validator.IsValid(new Uri("https://example.com/app?returnUrl=https://evil.com")), Is.False);
            Assert.That(validator.IsValid(new Uri("https://example.com/app#token")), Is.False);
        }
    }

    [Test]
    public void IsValidReturnsFalseForRootSubPath()
    {
        var options = new UriValidationOptions();
        options.AllowedCallbackUris.Add("https://example.com");
        var validator = new UriValidator(Options.Create(options));

        Assert.That(validator.IsValid(new Uri("https://example.com/anything")), Is.False);
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
