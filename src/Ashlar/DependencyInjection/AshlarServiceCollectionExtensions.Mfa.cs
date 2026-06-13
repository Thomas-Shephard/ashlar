// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's recovery code authentication provider and management service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional recovery code configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRecoveryCodes(
        this IServiceCollection services,
        Action<RecoveryCodeOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions<RecoveryCodeOptions>()
            .Validate(RecoveryCodeOptions.Validate, "Recovery code options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthenticationProvider, RecoveryCodeAuthenticationProvider>());
        services.TryAddScoped(provider => new RecoveryCodeServiceDependencies(
            provider.GetRequiredService<IOptions<RecoveryCodeOptions>>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<ISecurityNotificationService>()));
        services.TryAddScoped<IRecoveryCodeService, RecoveryCodeService>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IPasswordHasher, PasswordHasherV1>());

        return services;
    }

    /// <summary>
    /// Registers Ashlar's TOTP authenticator MFA provider and management service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional TOTP configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarTotp(
        this IServiceCollection services,
        Action<TotpOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions<TotpOptions>()
            .Validate(TotpOptions.Validate, "TOTP options are invalid.")
            .ValidateOnStart();
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
    /// Registers Ashlar's generic multi-factor authentication handshake infrastructure.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional MFA handshake configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarMfaHandshakes(
        this IServiceCollection services,
        Action<AuthenticationHandshakeOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions<AuthenticationHandshakeOptions>()
            .Validate(AuthenticationHandshakeOptions.Validate, "Authentication handshake options are invalid.")
            .ValidateOnStart();
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
            provider.GetService<IUserRepository>(),
            provider.GetService<ISecurityNotificationService>()));
        services.TryAddScoped<IAuthenticationHandshakeService, AuthenticationHandshakeService>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's remembered MFA device core service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional remembered MFA device configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRememberedMfaDevices(
        this IServiceCollection services,
        Action<RememberedMfaDeviceOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.AddOptions<RememberedMfaDeviceOptions>()
            .Validate(RememberedMfaDeviceOptions.Validate, "Remembered MFA device options are invalid.")
            .ValidateOnStart();
        if (configure != null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped(provider => new RememberedMfaDeviceServiceDependencies(
            provider.GetService<IOptions<RememberedMfaDeviceOptions>>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<ILoggerFactory>()));
        services.TryAddScoped<IRememberedMfaDeviceService, RememberedMfaDeviceService>();
        services.TryAddSingleton<ISecureTokenGenerator, SecureTokenGenerator>();
        services.TryAddSingleton<ISecureTokenHasher, Sha256TokenHasher>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's MFA policy and authentication orchestration services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional MFA orchestration configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
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
        services.TryAddScoped(provider => new AuthenticationOrchestratorDependencies(
            provider.GetService<IOptions<MfaOrchestrationOptions>>(),
            provider,
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationOrchestrator>>()));
        services.TryAddScoped<IAuthenticationOrchestrator, AuthenticationOrchestrator>();

        return services;
    }

    /// <summary>
    /// Explicitly registers the no-MFA policy evaluator.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
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
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Configures the factors required for every active user.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRequireMfaForAllUsers(
        this IServiceCollection services,
        Action<RequireMfaForAllUsersPolicyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<RequireMfaForAllUsersPolicyOptions>()
            .Configure(configure)
            .Validate(RequireMfaForAllUsersPolicyOptions.Validate, "At least one non-empty required factor must be configured.")
            .ValidateOnStart();

        return services.AddAshlarMfaPolicyEvaluator<RequireMfaForAllUsersPolicyEvaluator>();
    }

    /// <summary>
    /// Registers a reusable policy evaluator that requires MFA when a qualifying active credential exists.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Configures the credential providers and factors that trigger MFA.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarRequireMfaWhenCredentialExists(
        this IServiceCollection services,
        Action<CredentialBackedMfaPolicyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<CredentialBackedMfaPolicyOptions>()
            .Configure(configure)
            .Validate(CredentialBackedMfaPolicyOptions.Validate, "At least one credential provider key and one non-empty required factor must be configured.")
            .ValidateOnStart();

        return services.AddAshlarMfaPolicyEvaluator<RequireMfaWhenCredentialExistsPolicyEvaluator>();
    }

    /// <summary>
    /// Adds a custom MFA policy evaluator to the composite policy.
    /// </summary>
    /// <typeparam name="T">The MFA policy evaluator implementation type.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
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
}
