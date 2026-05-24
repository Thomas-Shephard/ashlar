// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Identity.Notifications;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's generic invitation and onboarding services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional invitation configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IInvitationRepository"/> or
    /// <see cref="IUserRepository"/> and <see cref="ICredentialRepository"/>. Applications should provide those dependencies explicitly,
    /// such as by using Ashlar.Postgres or custom repository implementations.
    /// </remarks>
    public static IServiceCollection AddAshlarInvitations(
        this IServiceCollection services,
        Action<InvitationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<IInvitationService, InvitationService>();
        services.TryAddScoped<InvitationStoreContext>();
        services.TryAddScoped<InvitationDependencies>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's generic bootstrap and first-admin setup services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional bootstrap configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarBootstrap(
        this IServiceCollection services,
        Action<BootstrapOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddAshlarInvitations();
        services.AddAshlarAuthorization();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<IBootstrapService, BootstrapService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's email verification services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email verification configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarEmailVerification(
        this IServiceCollection services,
        Action<EmailVerificationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped(provider => new EmailVerificationServiceDependencies(
            provider.GetRequiredService<IdentityContext>(),
            provider.GetRequiredService<SecureTokenContext>(),
            provider.GetRequiredService<IdentityInfrastructureContext>(),
            provider.GetRequiredService<IdentityAuditContext>(),
            provider.GetService<IOptions<EmailVerificationOptions>>()));
        services.TryAddScoped<IEmailVerificationService, EmailVerificationService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's email change services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional email change configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarEmailChange(
        this IServiceCollection services,
        Action<EmailChangeOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped(provider => new EmailChangeDependencies(
            provider.GetRequiredService<IdentityContext>(),
            provider.GetRequiredService<SecureTokenContext>(),
            provider.GetRequiredService<IdentityInfrastructureContext>(),
            provider.GetRequiredService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<ISecretProtector>(),
            provider.GetRequiredService<IdentityAuditContext>()));
        services.TryAddScoped<IEmailChangeService, EmailChangeService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's generic security notification services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional security notification configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityNotifications(
        this IServiceCollection services,
        Action<SecurityNotificationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<ISecurityNotificationSuppressionStore, InMemorySecurityNotificationSuppressionStore>();
        services.TryAddScoped<ISecurityNotificationService, SecurityNotificationService>();

        return services;
    }
}
