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
using Microsoft.Extensions.Options;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's recovery code authentication provider and management service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional recovery code configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>Recovery-code mutations require an <see cref="AshlarDurableTransactionProvider"/> and a transaction-bound <see cref="SecurityEventFanOutSink"/>.</remarks>
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
        services.TryAddScoped(provider =>
        {
            var timeProvider = provider.GetService<TimeProvider>() ?? TimeProvider.System;
            return new RecoveryCodeServiceDependencies(
                provider.GetRequiredService<IOptions<RecoveryCodeOptions>>(),
                new ActiveSessionFreshProofValidator(
                provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
                    timeProvider),
                timeProvider,
                provider.GetRequiredService<SecurityEventFanOutSink>(),
                provider.GetService<ISecurityNotificationService>(),
                provider.GetRequiredService<IAccountSecurityOperationAuthorizer>());
        });
        services.TryAddScoped(provider => new RecoveryCodeService(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<ICredentialRepository>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<PasswordHasherSelector>(),
            provider.GetRequiredService<RecoveryCodeServiceDependencies>()));
        services.TryAddScoped<IRecoveryCodeService>(provider => provider.GetRequiredService<RecoveryCodeService>());
        services.TryAddScoped<IRecoveryCodeMutationExecutor>(provider => provider.GetRequiredService<RecoveryCodeService>());
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IPasswordHasher, PasswordHasherV1>());

        return services;
    }

    /// <summary>
    /// Registers Ashlar's TOTP authenticator MFA provider and management service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional TOTP configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>TOTP mutations require an <see cref="AshlarDurableTransactionProvider"/> and a transaction-bound <see cref="SecurityEventFanOutSink"/>.</remarks>
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
        services.TryAddScoped(provider =>
        {
            var timeProvider = provider.GetService<TimeProvider>() ?? TimeProvider.System;
            return new TotpServiceDependencies(
                provider.GetRequiredService<IOptions<TotpOptions>>(),
                new ActiveSessionFreshProofValidator(
                provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
                    timeProvider),
                timeProvider,
                provider.GetRequiredService<SecurityEventFanOutSink>(),
                provider.GetService<ISecurityNotificationService>());
        });
        services.TryAddScoped(provider => new TotpService(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<ICredentialRepository>(),
            provider.GetRequiredService<ICredentialService>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<IEnumerable<IAuthenticationProvider>>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredService<TotpServiceDependencies>()));
        services.TryAddScoped<ITotpService>(provider => provider.GetRequiredService<TotpService>());

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
            provider.GetAshlarProviderService<IUserRepository>(),
            provider.GetService<ISecurityNotificationService>()));
        services.TryAddScoped(provider => ActivatorUtilities.CreateInstance<AuthenticationHandshakeService>(provider,
            provider.GetRequiredAshlarProviderService<IAuthenticationHandshakeRepository>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>()));
        services.TryAddScoped<IAuthenticationHandshakeService>(provider => provider.GetRequiredService<AuthenticationHandshakeService>());
        services.TryAddScoped<IAuthenticationHandshakeOrchestrationService>(provider => provider.GetRequiredService<AuthenticationHandshakeService>());
        services.TryAddScoped<IAuthenticationHandshakeCompletionService>(provider =>
            provider.GetRequiredService<AuthenticationHandshakeService>());

        return services;
    }

    /// <summary>
    /// Registers Ashlar's remembered MFA device core service.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional remembered MFA device configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>Remembered-device mutations require an <see cref="AshlarDurableTransactionProvider"/> and a transaction-bound <see cref="SecurityEventFanOutSink"/>.</remarks>
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
            provider.GetRequiredService<SecurityEventFanOutSink>()));
        services.TryAddScoped(provider => new RememberedMfaDeviceService(
            provider.GetRequiredAshlarProviderService<IRememberedMfaDeviceRepository>(),
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredService<ISecureTokenGenerator>(),
            provider.GetRequiredService<ISecureTokenHasher>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<RememberedMfaDeviceServiceDependencies>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<RememberedMfaDeviceService>>()));
        services.TryAddScoped<IRememberedMfaDeviceService>(provider => provider.GetRequiredService<RememberedMfaDeviceService>());
        services.TryAddScoped<IRememberedMfaDeviceMutationExecutor>(provider => provider.GetRequiredService<RememberedMfaDeviceService>());
        services.TryAddSingleton<ISecureTokenGenerator, SecureTokenGenerator>();
        services.TryAddSingleton<ISecureTokenHasher, Sha256TokenHasher>();

        return services;
    }

    /// <summary>
    /// Registers Ashlar's MFA authentication orchestration services without selecting an MFA policy.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional MFA orchestration configuration.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// This connects primary authentication to MFA policy evaluation and handshake management. Register
    /// <see cref="AddAshlarNoMfaPolicy(IServiceCollection)" />, <see cref="AddAshlarRequireMfaForAllUsers(IServiceCollection, Action{RequireMfaForAllUsersPolicyOptions})" />,
    /// <see cref="AddAshlarRequireMfaWhenCredentialExists(IServiceCollection, Action{CredentialBackedMfaPolicyOptions})" />, or a custom policy evaluator before resolving
    /// <see cref="IAuthenticationOrchestrator" />.
    /// </remarks>
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

        services.TryAddScoped(provider => new AuthenticationOrchestratorDependencies(
            provider.GetService<IOptions<MfaOrchestrationOptions>>(),
            provider,
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationOrchestrator>>(),
            provider.GetRequiredService<IAuthenticationHandshakeOrchestrationService>()));
        services.TryAddScoped<IAuthenticationOrchestrator>(provider => new AuthenticationOrchestrator(
            provider.GetRequiredService<IAuthenticationPipeline>(),
            provider.GetRequiredService<IAuthenticationFactorPipeline>(),
            provider.GetRequiredService<IAuthenticationHandshakeService>(),
            provider.GetRequiredService<IAuthenticationHandshakeCompletionService>(),
            provider.GetRequiredService<IMfaPolicyEvaluator>(),
            provider.GetRequiredService<IAuthenticationProviderRegistry>(),
            provider.GetRequiredService<AuthenticationOrchestratorDependencies>()));

        return services;
    }

    /// <summary>
    /// Explicitly registers the no-MFA policy evaluator for applications that want orchestration without policy-required MFA.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarNoMfaPolicy(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMfaOrchestration();
        services.Replace(ServiceDescriptor.Scoped<IMfaPolicyEvaluator, NoMfaPolicyEvaluator>());

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

        services.TryAddScoped(provider => ActivatorUtilities.CreateInstance<RequireMfaWhenCredentialExistsPolicyEvaluator>(provider,
            provider.GetRequiredAshlarProviderService<ICredentialRepository>()));
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
