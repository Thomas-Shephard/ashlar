using System.Net;
using Ashlar.AspNetCore.Middleware;
using Microsoft.AspNetCore.Http;

namespace Ashlar.AspNetCore.Tests;

public sealed class RequireIpAddressMiddlewareTests
{
    [Test]
    public void ConstructorRejectsNullNextDelegate()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var exception = Assert.Throws<ArgumentNullException>(() => _ = new RequireIpAddressMiddleware(null!));

        Assert.That(exception.ParamName, Is.EqualTo("next"));
    }

    [Test]
    public async Task InvokeAsyncReturnsBadRequestWhenRemoteIpAddressIsMissing()
    {
        var nextCalled = false;
        var middleware = new RequireIpAddressMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status400BadRequest));
            Assert.That(nextCalled, Is.False);
        }
    }

    [Test]
    public async Task InvokeAsyncCallsNextWhenRemoteIpAddressIsPresent()
    {
        var nextCalled = false;
        var middleware = new RequireIpAddressMiddleware(context =>
        {
            nextCalled = true;
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext { Connection = { RemoteIpAddress = IPAddress.Loopback } };

        await middleware.InvokeAsync(context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(nextCalled, Is.True);
            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status204NoContent));
        }
    }
}
