using Ashlar.AspNetCore.Middleware;

#pragma warning disable IDE0130
namespace Microsoft.AspNetCore.Builder;
#pragma warning restore IDE0130

public static class AshlarApplicationBuilderExtensions
{
    /// <summary>
    /// Adds middleware to the pipeline that returns a 400 Bad Request if the client's IP address cannot be determined.
    /// This helps prevent denial-of-service vectors against rate limiters that depend on IP addresses.
    /// </summary>
    public static IApplicationBuilder UseAshlarRequireIpAddress(this IApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.UseMiddleware<RequireIpAddressMiddleware>();
    }
}
