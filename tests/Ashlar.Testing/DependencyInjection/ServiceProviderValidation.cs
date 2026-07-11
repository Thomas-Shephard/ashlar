using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Testing.DependencyInjection;

/// <summary>
/// Builds service providers with strict dependency injection validation for composition tests.
/// </summary>
public static class ServiceProviderValidation
{
    /// <summary>
    /// Builds a service provider with scope and build-time validation enabled, then resolves selected services.
    /// </summary>
    /// <param name="services">The service registrations to validate.</param>
    /// <param name="servicesToResolve">Services that should be resolved from a validation scope.</param>
    /// <returns>The validated root service provider. The caller owns disposal.</returns>
    public static ServiceProvider BuildValidatedServiceProvider(
        IServiceCollection services,
        params Type[] servicesToResolve)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(servicesToResolve);

        var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true
        });

        var scope = provider.CreateAsyncScope();

        try
        {
            foreach (var serviceType in servicesToResolve)
            {
                _ = scope.ServiceProvider.GetRequiredService(serviceType);
            }
        }
        catch
        {
            var scopeDisposal = scope.DisposeAsync();
            scopeDisposal.AsTask().GetAwaiter().GetResult();
            var providerDisposal = provider.DisposeAsync();
            providerDisposal.AsTask().GetAwaiter().GetResult();
            throw;
        }

        try
        {
            scope.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch
        {
            provider.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }

        return provider;
    }

    /// <summary>
    /// Creates a service collection, applies configuration, and builds it with strict dependency injection validation.
    /// </summary>
    /// <param name="configure">Adds service registrations to the collection.</param>
    /// <param name="servicesToResolve">Services that should be resolved from a validation scope.</param>
    /// <returns>The validated root service provider. The caller owns disposal.</returns>
    public static ServiceProvider BuildValidatedServiceProvider(
        Action<IServiceCollection> configure,
        params Type[] servicesToResolve)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var services = new ServiceCollection();
        configure(services);
        return BuildValidatedServiceProvider(services, servicesToResolve);
    }
}
