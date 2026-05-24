// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Messaging;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's URI validation services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAshlarUriValidation(
        this IServiceCollection services,
        Action<UriValidationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<IUriValidator, UriValidator>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's framework-neutral messaging services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAshlarMessaging(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IEmailSender, NullEmailSender>();

        return services;
    }
}
