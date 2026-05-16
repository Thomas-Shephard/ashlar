// ReSharper disable CheckNamespace

using Ashlar.Auditing;
using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

/// <summary>
/// Provides dependency injection registration helpers for Ashlar identity services.
/// </summary>
/// <returns>The operation result.</returns>
public static class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's core identity services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <param name="configureSessions">The configure sessions value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IIdentityRepository"/> or
    /// <see cref="ISecretProtector"/>. Applications should provide those dependencies explicitly.
    /// </remarks>
    public static IServiceCollection AddAshlarIdentity(
        this IServiceCollection services,
        Action<IdentityServiceOptions>? configure = null,
        Action<AuthenticationSessionOptions>? configureSessions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMessaging();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        if (configureSessions != null)
        {
            services.Configure(configureSessions);
        }

        // IdentityService has multiple public constructors; use the full dependency graph explicitly.
        services.TryAdd(new ServiceDescriptor(
            typeof(IIdentityService),
            provider => new IdentityService(
                provider.GetRequiredService<IIdentityRepository>(),
                provider.GetRequiredService<IAuthenticationProviderRegistry>(),
                provider.GetRequiredService<ICredentialService>(),
                provider.GetRequiredService<IAuthenticationPipeline>(),
                provider.GetRequiredService<IAshlarTransactionProvider>(),
                provider.GetService<ISecurityEventSink>(),
                provider.GetService<TimeProvider>()),
            ServiceLifetime.Scoped));
        services.TryAddScoped<IAuthenticationPipeline, AuthenticationPipeline>();
        services.TryAddScoped<IAuthenticationProviderRegistry, AuthenticationProviderRegistry>();
        services.TryAddScoped<ICredentialService, CredentialService>();
        services.TryAddScoped(provider => new AuthenticationSessionServiceDependencies(
            provider.GetService<AuthenticationSessionOptions>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IIdentityRepository>(),
            provider.GetService<ISecurityNotificationService>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationSessionService>>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>()));
        services.TryAddScoped<IAuthenticationSessionService, AuthenticationSessionService>();
        services.TryAddScoped<IdentityContext>();
        services.TryAddScoped(provider => new IdentityInfrastructureContext(
            provider.GetRequiredService<IEmailSender>(),
            provider.GetRequiredService<IAuthenticationRateLimiter>(),
            provider.GetRequiredService<IUriValidator>()));
        services.TryAddScoped(provider => new IdentityAuditContext(
            provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<ISecurityEventSink>(),
            provider.GetService<ISecurityNotificationService>()));
        services.TryAddScoped<PasswordHasherSelector>();
        services.TryAddSingleton<ISecureTokenGenerator, SecureTokenGenerator>();
        services.TryAddSingleton<ISecureTokenHasher, Sha256TokenHasher>();
        services.TryAddSingleton<SecureTokenContext>();
        services.TryAddSingleton<ISecurityEventSink, NullSecurityEventSink>();
        services.TryAddSingleton<IAuthenticationRateLimiter, InMemoryAuthenticationRateLimiter>();
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<IdentityServiceOptions>>().Value);
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthenticationSessionOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarTransactionProvider, NullTransactionProvider>();
        services.AddAshlarUriValidation();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's URI validation services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarMessaging(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IEmailSender, NullEmailSender>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's framework-neutral authorization grant services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IAuthorizationGrantRepository"/>.
    /// Applications should provide that dependency explicitly, such as by using Ashlar.Postgres.
    /// </remarks>
    public static IServiceCollection AddAshlarAuthorization(
        this IServiceCollection services,
        Action<AuthorizationGrantOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<AuthorizationGrantOptions>()
            .Validate(AuthorizationGrantOptions.Validate, "Authorization grant options are invalid.");
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthorizationGrantOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ISecurityEventSink, NullSecurityEventSink>();
        services.TryAddScoped<IAuthorizationGrantService, AuthorizationGrantService>();
        services.TryAddScoped<IAuthorizationEvaluator, AuthorizationEvaluator>();

        return services;
    }

    /// <summary>
    /// Registers an authentication provider implementation.
    /// </summary>
    /// <typeparam name="TProvider">The tprovider type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAuthenticationProvider<TProvider>(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TProvider : class, IAuthenticationProvider
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(IAuthenticationProvider), typeof(TProvider), lifetime));

        return services;
    }

    /// <summary>
    /// Registers an authentication provider factory.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="implementationFactory">The implementation factory value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// Use this overload when multiple named providers are backed by the same implementation type.
    /// </remarks>
    public static IServiceCollection AddAuthenticationProvider(
        this IServiceCollection services,
        Func<IServiceProvider, IAuthenticationProvider> implementationFactory,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        services.AddAshlarIdentity();
        services.Add(new ServiceDescriptor(typeof(IAuthenticationProvider), implementationFactory, lifetime));

        return services;
    }

    /// <summary>
    /// Registers a password hasher implementation.
    /// </summary>
    /// <typeparam name="THasher">The thasher type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddPasswordHasher<THasher>(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where THasher : class, IPasswordHasher
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(IPasswordHasher), typeof(THasher), lifetime));

        return services;
    }

    /// <summary>
    /// Registers a password hasher factory.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="implementationFactory">The implementation factory value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddPasswordHasher(
        this IServiceCollection services,
        Func<IServiceProvider, IPasswordHasher> implementationFactory,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        services.AddAshlarIdentity();
        services.Add(new ServiceDescriptor(typeof(IPasswordHasher), implementationFactory, lifetime));

        return services;
    }

    /// <summary>
    /// Registers Ashlar's passwordless email code sign-in provider and issuing service.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarEmailCodeSignIn(
        this IServiceCollection services,
        Action<EmailCodeSignInOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

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
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarMagicLinkSignIn(
        this IServiceCollection services,
        Action<MagicLinkSignInOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, MagicLinkAuthenticationProvider>());
        services.TryAddScoped(provider => provider.GetServices<IAuthenticationProvider>().OfType<MagicLinkAuthenticationProvider>().First());
        services.TryAddScoped<MagicLinkSignInDependencies>();
        services.TryAddScoped<IMagicLinkSignInService, MagicLinkSignInService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's recovery code authentication provider and management service.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarRecoveryCodes(
        this IServiceCollection services,
        Action<RecoveryCodeOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, RecoveryCodeAuthenticationProvider>());
        services.TryAddScoped<IRecoveryCodeService, RecoveryCodeService>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IPasswordHasher, PasswordHasherV1>());

        return services;
    }

    /// <summary>
    /// Registers Ashlar's TOTP authenticator MFA provider and management service.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarTotp(
        this IServiceCollection services,
        Action<TotpOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        services.AddOptions<TotpOptions>()
            .Validate(TotpOptions.Validate, "TOTP options are invalid.");
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, TotpAuthenticationProvider>());
        services.TryAddScoped(provider => new TotpServiceDependencies(
            provider.GetRequiredService<IOptions<TotpOptions>>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<ISecurityNotificationService>()));
        services.TryAddScoped<ITotpService, TotpService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's generic invitation and onboarding services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IInvitationRepository"/> or
    /// <see cref="IIdentityRepository"/>. Applications should provide those dependencies explicitly,
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
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
    /// Registers <see cref="DataProtectionSecretProtector"/> as Ashlar's secret protector.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="lifetime">The lifetime value.</param>
    /// <returns>The operation result.</returns>
    /// <remarks>
    /// The application must also register ASP.NET Core Data Protection services or another
    /// <see cref="Microsoft.AspNetCore.DataProtection.IDataProtectionProvider"/>.
    /// </remarks>
    public static IServiceCollection AddAshlarDataProtectionSecretProtector(
        this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAdd(new ServiceDescriptor(typeof(ISecretProtector), typeof(DataProtectionSecretProtector), lifetime));

        return services;
    }

    /// <summary>
    /// Registers Ashlar's generic multi-factor authentication handshake infrastructure.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarMfaHandshakes(
        this IServiceCollection services,
        Action<AuthenticationHandshakeOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthenticationHandshakeOptions>>().Value);
        services.TryAddScoped(provider => new AuthenticationHandshakeServiceDependencies(
            provider.GetRequiredService<IOptions<AuthenticationHandshakeOptions>>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IAuthenticationRateLimiter>(),
            provider.GetService<IIdentityRepository>(),
            provider.GetService<ISecurityNotificationService>()));
        services.TryAddScoped<IAuthenticationHandshakeService, AuthenticationHandshakeService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's MFA policy and authentication orchestration services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarMfaOrchestration(
        this IServiceCollection services,
        Action<MfaOrchestrationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddAshlarMfaHandshakes();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<IMfaPolicyEvaluator, MfaPolicyEvaluator>();
        services.TryAddScoped<IAuthenticationOrchestrator, AuthenticationOrchestrator>();

        return services;
    }

    /// <summary>
    /// Explicitly registers the no-MFA policy evaluator.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarNoMfaPolicy(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMfaOrchestration();
        services.Replace(ServiceDescriptor.Scoped<IMfaPolicyEvaluator, MfaPolicyEvaluator>());

        return services;
    }

    /// <summary>
    /// Registers a reusable policy evaluator that requires MFA for every active user.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarRequireMfaForAllUsers(
        this IServiceCollection services,
        Action<RequireMfaForAllUsersPolicyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<RequireMfaForAllUsersPolicyOptions>()
            .Configure(configure)
            .Validate(RequireMfaForAllUsersPolicyOptions.Validate, "At least one non-empty required factor must be configured.");

        return services.AddAshlarMfaPolicyEvaluator<RequireMfaForAllUsersPolicyEvaluator>();
    }

    /// <summary>
    /// Registers a reusable policy evaluator that requires MFA when a qualifying active credential exists.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarRequireMfaWhenCredentialExists(
        this IServiceCollection services,
        Action<CredentialBackedMfaPolicyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<CredentialBackedMfaPolicyOptions>()
            .Configure(configure)
            .Validate(CredentialBackedMfaPolicyOptions.Validate, "At least one credential provider key and one non-empty required factor must be configured.");

        return services.AddAshlarMfaPolicyEvaluator<RequireMfaWhenCredentialExistsPolicyEvaluator>();
    }

    /// <summary>
    /// Adds a custom MFA policy evaluator to the composite policy.
    /// </summary>
    /// <typeparam name="T">The result value type.</typeparam>
    /// <param name="services">The services value.</param>
    /// <returns>The operation result.</returns>
    public static IServiceCollection AddAshlarMfaPolicyEvaluator<T>(this IServiceCollection services)
        where T : class, IMfaPolicyEvaluator
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMfaOrchestration();
        services.TryAddScoped<T>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IMfaPolicyEvaluatorComponent, MfaPolicyEvaluatorComponent<T>>());
        services.Replace(ServiceDescriptor.Scoped<IMfaPolicyEvaluator, CompositeMfaPolicyEvaluator>());

        return services;
    }

    /// <summary>
    /// Registers Ashlar's email verification services.
    /// </summary>
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <returns>The operation result.</returns>
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
