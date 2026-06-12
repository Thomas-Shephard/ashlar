using Ashlar.Messaging;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ashlar.Email.Smtp.Tests;

[TestFixture]
internal sealed class AshlarSmtpServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarSmtpEmailTransportShouldRegisterServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarSmtpEmailTransport(options =>
        {
            options.Host = "localhost";
        });
        var provider = services.BuildServiceProvider();

        var transport = provider.GetService<IEmailTransport>();
        Assert.That(transport, Is.Not.Null);
        Assert.That(transport, Is.InstanceOf<SmtpEmailTransport>());

        var options = provider.GetRequiredService<IOptions<SmtpEmailOptions>>().Value;
        Assert.That(options.Host, Is.EqualTo("localhost"));
    }

    [Test]
    public void AddAshlarSmtpEmailSenderShouldRegisterServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarSmtpEmailSender(options =>
        {
            options.Host = "localhost";
        });
        var provider = services.BuildServiceProvider();

        var sender = provider.GetService<IEmailSender>();
        Assert.That(sender, Is.Not.Null);
        Assert.That(sender, Is.InstanceOf<SmtpEmailSender>());

        var transport = provider.GetService<IEmailTransport>();
        Assert.That(transport, Is.Not.Null);
    }

    [Test]
    public void SmtpEmailTransportCompositionBuildsWithStrictValidationAndPreservesCustomSender()
    {
        var customSender = new TestEmailSender();
        var services = new ServiceCollection();
        services.AddSingleton<IEmailSender>(customSender);

        services.AddAshlarSmtpEmailTransport(options => options.Host = "localhost");
        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IEmailTransport),
            typeof(IEmailSender));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<IEmailTransport>(), Is.TypeOf<SmtpEmailTransport>());
            Assert.That(provider.GetRequiredService<IEmailSender>(), Is.SameAs(customSender));
        }
    }

    [Test]
    public void SmtpEmailSenderCompositionBuildsWithStrictValidationAndReplacesCustomSender()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IEmailSender, TestEmailSender>();

        services.AddAshlarSmtpEmailSender(options => options.Host = "localhost");
        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IEmailTransport),
            typeof(IEmailSender));

        Assert.That(provider.GetRequiredService<IEmailSender>(), Is.TypeOf<SmtpEmailSender>());
    }

    private sealed class TestEmailSender : IEmailSender
    {
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
