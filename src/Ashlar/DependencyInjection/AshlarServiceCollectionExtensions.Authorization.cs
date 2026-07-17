// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's framework-neutral authorization grant services.
    /// </summary>
    /// <param name="services">Service collection to add authorization services to.</param>
    /// <param name="configure">Optional authorization grant configuration callback.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// This method intentionally does not register grant persistence.
    /// Applications should add an Ashlar persistence provider, such as Ashlar.Postgres.
    /// </remarks>
    public static IServiceCollection AddAshlarAuthorization(
        this IServiceCollection services,
        Action<AuthorizationGrantOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarConfigurationValidation();
        services.AddOptions<AuthorizationGrantOptions>()
            .Validate(AuthorizationGrantOptions.Validate, "Authorization grant options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthorizationGrantOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.Replace(ServiceDescriptor.Scoped(provider => new SecurityEventFanOutSink(
            provider.GetAshlarProviderService<IPersistentSecurityEventSink>(),
            provider.GetServices<ISecurityEventHandler>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<SecurityEventFanOutSink>>(),
            provider.GetService<AshlarDurableTransactionProvider>(),
            provider.GetServices<IDurableSecurityEventFanOutHandler>())));
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
        services.TryAddScoped(provider => new AuthorizationGrantService(
            provider.GetRequiredAshlarProviderService<IAuthorizationGrantRepository>(),
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredService<SecurityEventFanOutSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetService<AuthorizationGrantOptions>(),
            provider.GetService<TimeProvider>(),
            new AuthorizationGrantMutationContext(
                provider.GetService<IAccountSecurityOperationAuthorizer>(),
                provider.GetAshlarProviderService<IAuthenticationSessionRepository>())));
        services.TryAddScoped<IAuthorizationGrantService>(provider => provider.GetRequiredService<AuthorizationGrantService>());
        services.TryAddScoped<IAuthorizationGrantBootstrapService>(provider => provider.GetRequiredService<AuthorizationGrantService>());
        services.TryAddScoped<IAuthorizationGrantAdministrationService>(provider => new AuthorizationGrantAdministrationService(
            provider.GetRequiredService<IAuthorizationGrantAdministrationRepository>(),
            provider.GetService<AuthorizationGrantOptions>(),
            provider.GetService<TimeProvider>(),
            new AuthorizationGrantMutationContext(
                provider.GetService<IAccountSecurityOperationAuthorizer>(),
                provider.GetAshlarProviderService<IAuthenticationSessionRepository>())));
        services.TryAddScoped<IAuthorizationEvaluator>(provider => new AuthorizationEvaluator(
            provider.GetRequiredAshlarProviderService<IAuthorizationGrantRepository>(),
            provider.GetService<AuthorizationGrantOptions>(),
            provider.GetService<TimeProvider>()));

        return services;
    }
}
