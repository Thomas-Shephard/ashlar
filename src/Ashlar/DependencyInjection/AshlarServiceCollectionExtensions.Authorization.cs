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
            .Validate(AuthorizationGrantOptions.Validate, "Authorization grant options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthorizationGrantOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<ISecurityEventSink, SecurityEventFanOutSink>();
        services.TryAddScoped(provider => new AuthorizationGrantService(
            provider.GetRequiredService<IAuthorizationGrantRepository>(),
            provider.GetRequiredService<IUserRepository>(),
            provider.GetService<AuthorizationGrantOptions>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IAshlarTransactionProvider>(),
            provider.GetService<IAccountSecurityOperationAuthorizer>(),
            provider.GetService<IAuthenticationSessionRepository>()));
        services.TryAddScoped<IAuthorizationGrantService>(provider => provider.GetRequiredService<AuthorizationGrantService>());
        services.TryAddScoped<IAuthorizationGrantBootstrapService>(provider => provider.GetRequiredService<AuthorizationGrantService>());
        services.TryAddScoped<IAuthorizationGrantAdministrationService>(provider => new AuthorizationGrantAdministrationService(
            provider.GetRequiredService<IAuthorizationGrantAdministrationRepository>(),
            provider.GetService<AuthorizationGrantOptions>(),
            provider.GetService<TimeProvider>()));
        services.TryAddScoped<IAuthorizationEvaluator, AuthorizationEvaluator>();

        return services;
    }
}
