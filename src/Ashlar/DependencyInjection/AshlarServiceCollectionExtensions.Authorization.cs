// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Auditing;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's framework-neutral authorization grant services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The service collection.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IAuthorizationGrantRepository"/>.
    /// Applications should provide that dependency explicitly, such as by using Ashlar.Postgres.
    /// </remarks>
    public static IServiceCollection AddAshlarAuthorization(
        this IServiceCollection services,
        Action<AuthorizationGrantOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarConfigurationValidation();
        services.AddOptions<AuthorizationGrantOptions>()
            .Validate(AuthorizationGrantOptions.Validate, "Authorization grant options are invalid.");
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthorizationGrantOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ISecurityEventSink, SecurityEventFanOutSink>();
        services.TryAddScoped<IAuthorizationGrantService, AuthorizationGrantService>();
        services.TryAddScoped<IAuthorizationEvaluator, AuthorizationEvaluator>();

        return services;
    }
}
