using Ashlar.Webhooks.SecurityEvents;

namespace Ashlar.Webhooks.Tests;

internal sealed class AshlarSecurityEventWebhookOptionsTests
{
    [Test]
    public void ValidateAcceptsEmptyEndpointList()
    {
        Assert.That(AshlarSecurityEventWebhookOptions.Validate(new AshlarSecurityEventWebhookOptions()), Is.True);
    }

    [Test]
    public void OptionsDefaultsAreSafe()
    {
        var options = new AshlarSecurityEventWebhookOptions();

        Assert.That(options.Timeout, Is.EqualTo(TimeSpan.FromSeconds(10)));
    }

    [TestCaseSource(nameof(InvalidOptions))]
    public void ValidateRejectsInvalidOptions(AshlarSecurityEventWebhookOptions? options)
    {
        Assert.That(AshlarSecurityEventWebhookOptions.Validate(options), Is.False);
    }

    [Test]
    public void EndpointValidateAcceptsHttpsEndpoint()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions
        {
            Name = "audit",
            Uri = new Uri("https://example.test/security-events"),
            SharedSecret = "shared-secret",
            Timeout = TimeSpan.FromSeconds(3)
        };
        endpoint.EventTypes.Add("ashlar.session.created");

        Assert.That(AshlarSecurityEventWebhookEndpointOptions.Validate(endpoint), Is.True);
    }

    [Test]
    public void EndpointDefaultsAreSafe()
    {
        var endpoint = new AshlarSecurityEventWebhookEndpointOptions();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(endpoint.Enabled, Is.True);
            Assert.That(endpoint.SharedSecret, Is.Null);
            Assert.That(endpoint.Timeout, Is.Null);
            Assert.That(endpoint.EventTypes, Is.Empty);
        }
    }

    private static IEnumerable<AshlarSecurityEventWebhookOptions?> InvalidOptions()
    {
        yield return null;
        yield return new AshlarSecurityEventWebhookOptions { Timeout = TimeSpan.Zero };
        yield return CreateOptions(null);
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = " ", Uri = new Uri("https://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("http://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("/relative", UriKind.Relative) });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), Timeout = TimeSpan.Zero });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit\r\nbad", Uri = new Uri("https://example.test") });
        yield return CreateOptions(new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test"), SharedSecret = " " });

        var blankEventType = new AshlarSecurityEventWebhookEndpointOptions { Name = "audit", Uri = new Uri("https://example.test") };
        blankEventType.EventTypes.Add(" ");
        yield return CreateOptions(blankEventType);
    }

    private static AshlarSecurityEventWebhookOptions CreateOptions(AshlarSecurityEventWebhookEndpointOptions? endpoint)
    {
        var options = new AshlarSecurityEventWebhookOptions();
        options.Endpoints.Add(endpoint!);
        return options;
    }
}
