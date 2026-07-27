// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>Test-only access to Ashlar's private provider service lane.</summary>
public static class TestProviderServiceCollectionExtensions
{
    /// <summary>Adds a test-owned provider service.</summary>
    /// <typeparam name="TService">The provider contract.</typeparam>
    /// <param name="services">The test service collection.</param>
    /// <param name="factory">The test service factory.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarProviderScoped<TService>(
        this IServiceCollection services,
        Func<IServiceProvider, TService> factory)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddScoped(provider => new AshlarProviderService<TService>(factory(provider)));
        return services;
    }

    /// <summary>Replaces a test-owned provider service.</summary>
    /// <typeparam name="TService">The provider contract.</typeparam>
    /// <param name="services">The test service collection.</param>
    /// <param name="factory">The replacement test service factory.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection ReplaceAshlarProviderScoped<TService>(
        this IServiceCollection services,
        Func<IServiceProvider, TService> factory)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.RemoveAll<AshlarProviderService<TService>>();
        return services.AddAshlarProviderScoped(factory);
    }
}
