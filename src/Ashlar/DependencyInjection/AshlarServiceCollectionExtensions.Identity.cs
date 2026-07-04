// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

public static partial class AshlarServiceCollectionExtensions
{
    /// <summary>
    /// Registers Ashlar's core identity services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional configuration for identity service behavior.</param>
    /// <param name="configureSessions">Optional configuration for authentication session behavior.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IUserRepository"/>, <see cref="ICredentialRepository"/>,
    /// <see cref="ISecretProtector"/>, <see cref="IAccountSecurityGuard"/>, or <see cref="IAshlarTransactionProvider"/>.
    /// Applications should provide those dependencies explicitly. Use <see cref="AddPermissiveAccountSecurityGuard"/>
    /// only when guarded account-security mutations may all proceed, and use <see cref="AddAshlarNullTransactions"/>
    /// only when no transaction atomicity is required.
    /// </remarks>
    public static IServiceCollection AddAshlarIdentity(
        this IServiceCollection services,
        Action<IdentityServiceOptions>? configure = null,
        Action<AuthenticationSessionOptions>? configureSessions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarMessaging();
        services.AddAshlarConfigurationValidation();
        services.AddOptions();
        if (configure != null)
        {
            services.Configure(configure);
        }

        if (configureSessions != null)
        {
            services.Configure(configureSessions);
        }

        services.AddOptions<PrimaryAuthenticationRateLimitOptions>()
            .Validate(PrimaryAuthenticationRateLimitOptions.Validate, "Primary authentication rate-limit options are invalid.")
            .ValidateOnStart();
        services.AddOptions<AuthenticationFactorRateLimitOptions>()
            .Validate(AuthenticationFactorRateLimitOptions.Validate, "Secondary factor rate-limit options are invalid.")
            .ValidateOnStart();
        services.AddOptions<AccountLockoutOptions>()
            .Validate(AccountLockoutOptions.Validate, "Account lockout options are invalid.")
            .ValidateOnStart();

        services.TryAdd(new ServiceDescriptor(
            typeof(IIdentityService),
            provider => new IdentityService(
                provider.GetRequiredService<IUserRepository>(),
                provider.GetRequiredService<IAuthenticationProviderRegistry>(),
                provider.GetRequiredService<ICredentialService>(),
                provider.GetRequiredService<IAuthenticationPipeline>(),
                provider.GetRequiredService<IAshlarTransactionProvider>(),
                new IdentityServiceDependencies(
                    provider.GetService<ISecurityEventSink>(),
                    provider.GetService<TimeProvider>(),
                    provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>())),
            ServiceLifetime.Scoped));
        services.TryAddScoped(provider => new AuthenticationPipelineDependencies(
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationPipeline>>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>(),
            provider.GetService<IAccountLockoutService>(),
            provider.GetRequiredService<IOptions<PrimaryAuthenticationRateLimitOptions>>().Value,
            provider.GetRequiredService<IOptions<AuthenticationFactorRateLimitOptions>>().Value,
            provider.GetRequiredService<IOptions<AccountLockoutOptions>>().Value));
        services.TryAddScoped(provider => new AuthenticationPipeline(
            provider.GetRequiredService<IAuthenticationProviderRegistry>(),
            provider.GetRequiredService<ICredentialService>(),
            provider.GetRequiredService<IAshlarTransactionProvider>(),
            provider.GetRequiredService<IPrimaryAuthenticationRateLimiter>(),
            provider.GetRequiredService<IAuthenticationFactorRateLimiter>(),
            provider.GetRequiredService<AuthenticationPipelineDependencies>()));
        services.TryAddScoped<IAuthenticationPipeline>(provider => provider.GetRequiredService<AuthenticationPipeline>());
        services.TryAddScoped<IAuthenticationFactorPipeline>(provider => provider.GetRequiredService<AuthenticationPipeline>());
        services.TryAddScoped<IPrimaryAuthenticationRateLimiter, PrimaryAuthenticationRateLimiter>();
        services.TryAddScoped<IAuthenticationFactorRateLimiter, AuthenticationFactorRateLimiter>();
        services.TryAddScoped<IAuthenticationProviderRegistry, AuthenticationProviderRegistry>();
        services.TryAddScoped(provider => new CredentialServiceDependencies(
            provider.GetService<IdentityServiceOptions>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<CredentialService>>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>()));
        services.TryAddScoped<ICredentialService, CredentialService>();
        services.TryAddScoped(provider => new AccountSecurityServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IUserSecurityEventSummaryRepository>(),
            provider.GetService<IOptions<TotpOptions>>(),
            provider.GetService<IOptions<RecoveryCodeOptions>>(),
            provider.GetService<IMfaPolicyEvaluator>(),
            provider.GetService<IAuthenticationProviderRegistry>(),
            provider.GetService<IRememberedMfaDeviceService>()));
        services.TryAddScoped<IAccountSecurityService, AccountSecurityService>();
        services.TryAddScoped(provider => new AccountLockoutServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>()));
        services.TryAddScoped<IAccountLockoutService>(provider =>
        {
            var repository = provider.GetService<IAccountLockoutRepository>();
            return repository == null
                ? DisabledAccountLockoutService.Instance
                : new AccountLockoutService(
                    repository,
                    provider.GetRequiredService<IOptions<AccountLockoutOptions>>(),
                    provider.GetService<AccountLockoutServiceDependencies>());
        });
        services.TryAddScoped<IUserAdministrationService, UserAdministrationService>();
        services.TryAddScoped<ICredentialAdministrationService, CredentialAdministrationService>();
        services.TryAddScoped<IAccountRecoveryAdministrationService>(provider => new AccountRecoveryAdministrationService(
            provider.GetRequiredService<IUserAdministrationService>(),
            provider.GetService<IRememberedMfaDeviceService>()));
        services.TryAddScoped<IAccountRecoveryAdministrationExecutor, AccountRecoveryAdministrationExecutor>();
        services.TryAddScoped(provider => new AccountLockoutAdministrationServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>()));
        services.TryAddScoped<IAccountLockoutAdministrationService>(provider => new AccountLockoutAdministrationService(
            provider.GetRequiredService<IAccountLockoutRepository>(),
            provider.GetService<AccountLockoutAdministrationServiceDependencies>()));
        services.TryAddScoped<ISecurityEventAdministrationService, SecurityEventAdministrationService>();
        services.TryAddScoped<IAuthenticationSessionAdministrationService, AuthenticationSessionAdministrationService>();
        services.TryAddScoped(provider => new AuthenticationSessionServiceDependencies(
            provider.GetRequiredService<IUserRepository>(),
            Options: provider.GetService<AuthenticationSessionOptions>(),
            TimeProvider: provider.GetService<TimeProvider>(),
            SecurityEventSink: provider.GetService<ISecurityEventSink>(),
            NotificationService: provider.GetService<ISecurityNotificationService>(),
            Logger: provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationSessionService>>(),
            LoggerFactory: provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>()));
        services.TryAddScoped<IAuthenticationSessionService, AuthenticationSessionService>();
        services.TryAddScoped<IStepUpAuthenticationService, StepUpAuthenticationService>();
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
        services.TryAddScoped<ISecurityEventSink, SecurityEventFanOutSink>();
        services.TryAddSingleton<InMemoryAuthenticationRateLimiter>();
        services.TryAddSingleton<IAuthenticationRateLimiter>(provider => provider.GetRequiredService<InMemoryAuthenticationRateLimiter>());
        services.TryAddScoped<IAuthenticationRateLimiterDiagnostics>(provider =>
        {
            var rateLimiter = provider.GetRequiredService<IAuthenticationRateLimiter>();
            var timeProvider = provider.GetRequiredService<TimeProvider>();
            if (rateLimiter is InMemoryAuthenticationRateLimiter inMemoryRateLimiter)
            {
                return new InMemoryAuthenticationRateLimiterDiagnostics(inMemoryRateLimiter, timeProvider);
            }

            return new NotSupportedAuthenticationRateLimiterDiagnostics(rateLimiter.GetType().Name, timeProvider);
        });
        services.TryAddScoped<IAshlarOperationsSummaryService, AshlarOperationsSummaryService>();
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<IdentityServiceOptions>>().Value);
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthenticationSessionOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.AddAshlarUriValidation();

        return services;
    }

    /// <summary>
    /// Explicitly registers the account-security guard that permits every account-state change.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// Use this only when the host deliberately allows account-state changes without application-specific business
    /// approval, risk review, tenant-specific policy, or separation-of-duties checks. Configuration validation reports
    /// this guard as permissive.
    /// </remarks>
    public static IServiceCollection AddPermissiveAccountSecurityGuard(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<IAccountSecurityGuard, PermissiveAccountSecurityGuard>();

        return services;
    }

    /// <summary>
    /// Explicitly registers the transaction provider that performs no transaction work.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// The <see langword="null" /> transaction provider provides no atomicity across multi-step identity operations. Use this only
    /// for tests, provider-less composition, or simple custom hosts that deliberately do not require coordinated
    /// repository transactions. Persistence providers should register a durable <see cref="IAshlarTransactionProvider"/>.
    /// </remarks>
    public static IServiceCollection AddAshlarNullTransactions(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<IAshlarTransactionProvider, NullTransactionProvider>();

        return services;
    }

    /// <summary>
    /// Registers authentication rate-limit administration operations for the configured provider repository.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// Host applications must protect this service with appropriate administrator authorization and step-up policy.
    /// </remarks>
    public static IServiceCollection AddAshlarAuthenticationRateLimitAdministration(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped(provider => new AuthenticationRateLimitAdministrationServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>()));
        services.TryAddScoped<IAuthenticationRateLimitAdministrationService>(provider =>
            new AuthenticationRateLimitAdministrationService(
                provider.GetRequiredService<IAuthenticationRateLimitAdministrationRepository>(),
                provider.GetService<AuthenticationRateLimitAdministrationServiceDependencies>()));

        return services;
    }

    /// <summary>
    /// Registers a security event handler for Ashlar security event fan-out.
    /// </summary>
    /// <typeparam name="THandler">The handler type.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventHandler<THandler>(this IServiceCollection services)
        where THandler : class, ISecurityEventHandler
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<ISecurityEventHandler, THandler>());

        return services;
    }

    /// <summary>
    /// Registers a security event handler factory for Ashlar security event fan-out.
    /// </summary>
    /// <typeparam name="THandler">The handler type.</typeparam>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="implementationFactory">The handler implementation factory.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    public static IServiceCollection AddAshlarSecurityEventHandler<THandler>(
        this IServiceCollection services,
        Func<IServiceProvider, THandler> implementationFactory)
        where THandler : class, ISecurityEventHandler
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        services.AddAshlarIdentity();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<ISecurityEventHandler, THandler>(implementationFactory));

        return services;
    }
}
