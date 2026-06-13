// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Identity.Providers.Email;
using Ashlar.Security.Hashing;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's passwordless email code sign-in provider and issuing service.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAshlarEmailCodeSignIn(
        this IServiceCollection services,
        Action<EmailCodeSignInOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMfaOrchestration();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.AddOptions<EmailCodeSignInOptions>()
            .Validate(EmailCodeSignInOptions.Validate, "Email code sign-in options are invalid.")
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, EmailCodeAuthenticationProvider>());
        services.TryAddScoped(provider => provider.GetServices<IAuthenticationProvider>().OfType<EmailCodeAuthenticationProvider>().First());
        services.TryAddScoped<EmailCodeSignInDependencies>();
        services.TryAddScoped<IEmailCodeSignInService, EmailCodeSignInService>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IPasswordHasher, PasswordHasherV1>());

        return services;
    }

    /// <summary>
    /// Registers Ashlar's magic-link email sign-in provider and issuing service.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddAshlarMagicLinkSignIn(
        this IServiceCollection services,
        Action<MagicLinkSignInOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMfaOrchestration();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.AddOptions<MagicLinkSignInOptions>()
            .Validate(MagicLinkSignInOptions.Validate, "Magic-link sign-in options are invalid.")
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, MagicLinkAuthenticationProvider>());
        services.TryAddScoped(provider => provider.GetServices<IAuthenticationProvider>().OfType<MagicLinkAuthenticationProvider>().First());
        services.TryAddScoped<MagicLinkSignInDependencies>();
        services.TryAddScoped<IMagicLinkSignInService, MagicLinkSignInService>();

        return services;
    }
}
