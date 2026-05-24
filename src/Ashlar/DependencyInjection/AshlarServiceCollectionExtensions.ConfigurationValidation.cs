// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Operational.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar provider-neutral configuration validation services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarConfigurationValidation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<IAshlarConfigurationValidator, AshlarConfigurationValidator>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAshlarConfigurationCheck, AshlarCoreConfigurationCheck>());

        return services;
    }
}
