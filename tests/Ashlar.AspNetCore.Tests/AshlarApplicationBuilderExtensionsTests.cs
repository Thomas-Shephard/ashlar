using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.AspNetCore.Tests;

public sealed class AshlarApplicationBuilderExtensionsTests
{
    [Test]
    public void UseAshlarRequireIpAddressRejectsNullBuilder()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarApplicationBuilderExtensions.UseAshlarRequireIpAddress(null!));

        Assert.That(exception.ParamName, Is.EqualTo("builder"));
    }

    [Test]
    public async Task UseAshlarRequireIpAddressAddsMiddlewareToPipeline()
    {
        var services = new ServiceCollection().BuildServiceProvider();
        var builder = new ApplicationBuilder(services);
        builder.UseAshlarRequireIpAddress();
        builder.Run(context =>
        {
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return Task.CompletedTask;
        });
        var app = builder.Build();
        var context = new DefaultHttpContext
        {
            RequestServices = services, Connection = { RemoteIpAddress = IPAddress.Loopback }
        };

        await app(context);

        Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status204NoContent));
    }
}
