// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
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
        services.AddOptions<InvitationOptions>()
            .Validate(InvitationOptions.Validate, "Invitation options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<IInvitationService, InvitationService>();
        services.TryAddScoped(provider => new InvitationAdministrationServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IAshlarTransactionProvider>()));
        services.TryAddScoped<IInvitationAdministrationService>(provider => new InvitationAdministrationService(
            provider.GetRequiredService<IInvitationRepository>(),
            provider.GetService<InvitationAdministrationServiceDependencies>()));
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
        services.AddOptions<BootstrapOptions>()
            .Validate(BootstrapOptions.Validate, "Bootstrap options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<IBootstrapService, BootstrapService>();
        services.TryAddScoped<BootstrapStoreContext>();
        services.TryAddScoped<BootstrapDependencies>();

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
        services.AddOptions<EmailVerificationOptions>()
            .Validate(EmailVerificationOptions.Validate, "Email verification options are invalid.")
            .ValidateOnStart();
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
        services.AddOptions<EmailChangeOptions>()
            .Validate(EmailChangeOptions.Validate, "Email change options are invalid.")
            .ValidateOnStart();
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
    /// Registers Ashlar's local password reset services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional password reset configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarPasswordReset(
        this IServiceCollection services,
        Action<PasswordResetOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions<PasswordResetOptions>()
            .Validate(PasswordResetOptions.Validate, "Password reset options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddEnumerable(ServiceDescriptor.Scoped<IPasswordHasher, PasswordHasherV1>());
        services.TryAddScoped(provider => new PasswordResetDependencies(
            provider.GetRequiredService<IdentityContext>(),
            provider.GetRequiredService<SecureTokenContext>(),
            provider.GetRequiredService<IdentityInfrastructureContext>(),
            provider.GetRequiredService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<PasswordHasherSelector>(),
            provider.GetRequiredService<IdentityAuditContext>(),
            provider.GetService<IRememberedMfaDeviceMutationExecutor>()));
        services.TryAddScoped<IPasswordResetService, PasswordResetService>();

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
