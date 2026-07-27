// ReSharper disable CheckNamespace
#pragma warning disable IDE0130
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130

using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
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
    internal static IServiceCollection AddProviderDurableTransactionProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IAshlarTransactionProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        AshlarProviderServiceCollection.TryAddProviderScoped<TProvider, TProvider>(services);
        services.Replace(ServiceDescriptor.Scoped<AshlarDurableTransactionProvider>(provider =>
        {
            var participants = provider.GetServices<AshlarDurableTransactionParticipantRegistration>()
                .Select(registration => provider.GetRequiredAshlarProviderService(registration.ServiceType))
                .ToArray();
            return AshlarDurableTransactionProvider.Create(provider.GetRequiredAshlarProviderService<TProvider>(), participants);
        }));

        return services;
    }

    internal static IServiceCollection AddProviderDurableTransactionParticipant<TParticipant>(this IServiceCollection services)
        where TParticipant : class
    {
        ArgumentNullException.ThrowIfNull(services);
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(AshlarDurableTransactionParticipantRegistration)
            && descriptor.ImplementationInstance is AshlarDurableTransactionParticipantRegistration registration
            && registration.ServiceType == typeof(TParticipant)))
        {
            services.AddSingleton(new AshlarDurableTransactionParticipantRegistration(typeof(TParticipant)));
        }
        return services;
    }

    /// <summary>Declares the core identity repositories as participants in the registered durable transaction provider.</summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection.</returns>
    internal static IServiceCollection AddProviderIdentityDurableTransactionParticipants(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddProviderDurableTransactionParticipant<IUserRepository>();
        services.AddProviderDurableTransactionParticipant<ICredentialRepository>();
        services.AddProviderDurableTransactionParticipant<IAccountLockoutRepository>();
        services.AddProviderDurableTransactionParticipant<IInvitationRepository>();
        services.AddProviderDurableTransactionParticipant<IAuthenticationSessionRepository>();
        services.AddProviderDurableTransactionParticipant<IRememberedMfaDeviceRepository>();
        services.AddProviderDurableTransactionParticipant<IPasskeyChallengeRepository>();
        services.AddProviderDurableTransactionParticipant<IAuthorizationGrantRepository>();
        return services;
    }

    /// <summary>
    /// Registers Ashlar's core identity services.
    /// </summary>
    /// <param name="services">The service collection to add registrations to.</param>
    /// <param name="configure">Optional configuration for identity service behavior.</param>
    /// <param name="configureSessions">Optional configuration for authentication session behavior.</param>
    /// <returns>The same service collection so calls can be chained.</returns>
    /// <remarks>
    /// This method intentionally does not register <see cref="IUserRepository"/>, <see cref="ICredentialRepository"/>,
    /// <see cref="ISecretProtector"/>, <see cref="IAccountSecurityGuard"/>, <see cref="IAccountSecurityOperationAuthorizer"/>,
    /// or <see cref="IAshlarTransactionProvider"/>.
    /// Install a persistence provider, or use the provider-authoring package when implementing one. Applications still
    /// provide the secret protector and account-security policies. Use <see cref="AddPermissiveAccountSecurityGuard"/>
    /// only when guarded account-security mutations may all proceed. Mutation-capable identity services require an
    /// <see cref="AshlarDurableTransactionProvider"/> and a transaction-bound <see cref="SecurityEventFanOutSink"/>
    /// using that same provider.
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
                provider.GetRequiredService<IAuthenticationProviderRegistry>(),
                provider.GetRequiredService<IAuthenticationPipeline>()),
            ServiceLifetime.Scoped));
        services.TryAddScoped(provider => new AuthenticationPipelineDependencies(
            provider.GetRequiredService<SecurityEventFanOutSink>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationPipeline>>(),
            provider.GetAshlarProviderService<IAccountLockoutRepository>() is { } lockoutRepository
                ? new AccountLockoutService(
                    lockoutRepository,
                    provider.GetRequiredService<IOptions<AccountLockoutOptions>>(),
                    provider.GetService<AccountLockoutServiceDependencies>())
                : null,
            provider.GetRequiredService<IOptions<PrimaryAuthenticationRateLimitOptions>>().Value,
            provider.GetRequiredService<IOptions<AuthenticationFactorRateLimitOptions>>().Value,
            provider.GetRequiredService<IOptions<AccountLockoutOptions>>().Value));
        services.TryAddScoped(provider => new AuthenticationPipeline(
            provider.GetRequiredService<IAuthenticationProviderRegistry>(),
            provider.GetRequiredService<ICredentialService>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<IPrimaryAuthenticationRateLimiter>(),
            provider.GetRequiredService<IAuthenticationFactorRateLimiter>(),
            provider.GetRequiredService<AuthenticationPipelineDependencies>()));
        services.TryAddScoped<IAuthenticationPipeline>(provider => provider.GetRequiredService<AuthenticationPipeline>());
        services.TryAddScoped<IAuthenticationFactorPipeline>(provider => provider.GetRequiredService<AuthenticationPipeline>());
        services.TryAddScoped<IPrimaryAuthenticationRateLimiter, PrimaryAuthenticationRateLimiter>();
        services.TryAddScoped<IAuthenticationFactorRateLimiter, AuthenticationFactorRateLimiter>();
        services.TryAddScoped<IAuthenticationProviderRegistry, AuthenticationProviderRegistry>();
        services.TryAddScoped<IUserProfileService>(provider => new UserProfileService(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.TryAddScoped(provider =>
        {
            var sink = provider.GetRequiredService<SecurityEventFanOutSink>();
            var transactions = provider.GetRequiredService<AshlarDurableTransactionProvider>();
            if (!sink.RequiresDurableTransaction || !ReferenceEquals(transactions, sink.TransactionProvider))
                throw new InvalidOperationException("Credential mutations require durable audit using the same transaction provider.");
            return new CredentialServiceDependencies(provider.GetService<IdentityServiceOptions>(), provider.GetService<TimeProvider>(), sink,
                provider.GetService<global::Microsoft.Extensions.Logging.ILogger<CredentialService>>());
        });
        services.TryAddScoped(provider => new CredentialService(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<ICredentialRepository>(),
            provider.GetRequiredService<ISecretProtector>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<CredentialServiceDependencies>()));
        services.TryAddScoped<ICredentialService>(provider => provider.GetRequiredService<CredentialService>());
        services.TryAddScoped<IValidatedExternalCredentialLinkService>(provider => provider.GetRequiredService<CredentialService>());
        services.TryAddScoped(provider => new AccountSecurityServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IUserSecurityEventSummaryRepository>(),
            provider.GetService<IOptions<TotpOptions>>(),
            provider.GetService<IOptions<RecoveryCodeOptions>>(),
            provider.GetService<IMfaPolicyEvaluator>(),
            provider.GetService<IAuthenticationProviderRegistry>(),
            provider.GetService<IRememberedMfaDeviceMutationExecutor>()));
        services.TryAddScoped(provider => new AccountSecurityService(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<ICredentialRepository>(),
            provider.GetRequiredService<IAuthenticationSessionMutationExecutor>(),
            provider.GetRequiredService<IAuthenticationSessionInventoryReader>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<IAccountSecurityGuard>(),
            provider.GetRequiredService<AccountSecurityServiceDependencies>()));
        services.TryAddScoped<IAccountSecurityService>(provider => provider.GetRequiredService<AccountSecurityService>());
        services.TryAddScoped<IAccountSecurityMutationExecutor>(provider => provider.GetRequiredService<AccountSecurityService>());
        services.TryAddScoped<IAccountSecurityPostureReader>(provider => provider.GetRequiredService<AccountSecurityService>());
        services.TryAddScoped<IAccountSecurityAdministrationService>(provider => new AccountSecurityAdministrationService(
            provider.GetRequiredService<IAccountSecurityMutationExecutor>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetService<TimeProvider>() ?? TimeProvider.System,
            provider.GetService<ISecurityEventSink>()));
        services.TryAddScoped(provider => new AccountLockoutServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>()));
        services.TryAddScoped<IUserAdministrationService>(provider => new UserAdministrationService(
            provider.GetRequiredAshlarProviderService<IUserAdministrationRepository>(),
            provider.GetRequiredService<IAccountSecurityPostureReader>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(),
            provider.GetService<TimeProvider>()));
        services.TryAddScoped<ICredentialAdministrationService>(provider => new CredentialAdministrationService(
            provider.GetRequiredAshlarProviderService<ICredentialAdministrationRepository>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(),
            provider.GetService<TimeProvider>()));
        services.TryAddScoped<IAccountRecoveryAdministrationService>(provider => new AccountRecoveryAdministrationService(
            provider.GetRequiredService<IUserAdministrationService>(),
            provider.GetService<IRememberedMfaDeviceReader>()));
        services.TryAddScoped(provider => new AccountLockoutAdministrationServiceDependencies(
            provider.GetService<TimeProvider>(),
            provider.GetRequiredService<SecurityEventFanOutSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>()));
        services.TryAddScoped<IAccountLockoutAdministrationService>(provider => new AccountLockoutAdministrationService(
            provider.GetRequiredAshlarProviderService<IAccountLockoutRepository>(),
            provider.GetRequiredService<AccountLockoutAdministrationServiceDependencies>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>()));
        services.TryAddScoped<IAccountLockoutAdministrationReader>(provider => new AccountLockoutAdministrationReader(
            provider.GetRequiredAshlarProviderService<IAccountLockoutRepository>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(), provider.GetService<TimeProvider>()));
        services.TryAddScoped<IRememberedMfaDeviceReader>(provider => new RememberedMfaDeviceReader(
            provider.GetRequiredAshlarProviderService<IRememberedMfaDeviceRepository>(), provider.GetService<TimeProvider>()));
        services.TryAddScoped<ISecurityEventAdministrationService>(provider => new SecurityEventAdministrationService(
            provider.GetRequiredAshlarProviderService<ISecurityEventAdministrationRepository>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(),
            provider.GetService<TimeProvider>()));
        services.TryAddScoped<IAuthenticationSessionAdministrationService>(provider => new AuthenticationSessionAdministrationService(
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionAdministrationRepository>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(),
            provider.GetService<TimeProvider>()));
        services.TryAddScoped(provider => new AuthenticationSessionServiceDependencies(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            Options: provider.GetService<AuthenticationSessionOptions>(),
            TimeProvider: provider.GetService<TimeProvider>(),
            SecurityEventSink: provider.GetRequiredService<SecurityEventFanOutSink>(),
            NotificationService: provider.GetService<ISecurityNotificationService>(),
            Logger: provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationSessionService>>(),
            OperationAuthorizer: provider.GetRequiredService<IAccountSecurityOperationAuthorizer>()));
        services.TryAddScoped(provider => new AuthenticationSessionService(
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
            provider.GetRequiredService<ISecureTokenHasher>(),
            provider.GetRequiredService<ISecureTokenGenerator>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>(),
            provider.GetRequiredService<AuthenticationSessionServiceDependencies>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationSessionService>>()));
        services.TryAddScoped<IAuthenticationSessionService>(provider => provider.GetRequiredService<AuthenticationSessionService>());
        services.TryAddScoped(provider => new AuthenticationSessionReader(
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(), provider.GetService<TimeProvider>()));
        services.TryAddScoped<IAuthenticationSessionReader>(provider => provider.GetRequiredService<AuthenticationSessionReader>());
        services.TryAddScoped<IAuthenticationSessionInventoryReader>(provider => provider.GetRequiredService<AuthenticationSessionReader>());
        services.TryAddScoped<IAuthenticationSessionMutationExecutor>(provider => provider.GetRequiredService<AuthenticationSessionService>());
        services.TryAddScoped<StepUpAuthenticationService>();
        services.TryAddScoped<IStepUpAuthenticationService>(provider => provider.GetRequiredService<StepUpAuthenticationService>());
        services.TryAddScoped(provider => new IdentityContext(
            provider.GetRequiredAshlarProviderService<IUserRepository>(),
            provider.GetRequiredAshlarProviderService<ICredentialRepository>(),
            provider.GetRequiredService<IIdentityService>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>()));
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
        services.Replace(ServiceDescriptor.Scoped(provider => new SecurityEventFanOutSink(
            provider.GetAshlarProviderService<IPersistentSecurityEventSink>(),
            provider.GetServices<ISecurityEventHandler>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<SecurityEventFanOutSink>>(),
            provider.GetService<AshlarDurableTransactionProvider>(),
            provider.GetServices<IDurableSecurityEventFanOutHandler>())));
        services.Replace(ServiceDescriptor.Scoped<ISecurityEventSink>(provider => provider.GetRequiredService<SecurityEventFanOutSink>()));
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
            provider.GetRequiredService<SecurityEventFanOutSink>(),
            provider.GetRequiredService<AshlarDurableTransactionProvider>()));
        services.TryAddScoped<IAuthenticationRateLimitAdministrationService>(provider =>
            new AuthenticationRateLimitAdministrationService(
                provider.GetRequiredAshlarProviderService<IAuthenticationRateLimitAdministrationRepository>(),
                provider.GetRequiredService<AuthenticationRateLimitAdministrationServiceDependencies>(),
                provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
                provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
                provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>()));
        services.TryAddScoped<IAuthenticationRateLimitAdministrationReader>(provider => new AuthenticationRateLimitAdministrationReader(
            provider.GetRequiredAshlarProviderService<IAuthenticationRateLimitAdministrationRepository>(),
            provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(), provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
            provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(), provider.GetService<TimeProvider>()));

        return services;
    }

    /// <summary>Records the authentication rate-limit provider and rejects a conflicting provider registration.</summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="providerName">The provider name used in configuration diagnostics.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarAuthenticationRateLimitProviderMarker(
        this IServiceCollection services,
        string providerName)
    {
        services.ValidateAshlarAuthenticationRateLimitProviderMarker(providerName);

        var existing = services
            .FirstOrDefault(descriptor => descriptor.ServiceType == typeof(AuthenticationRateLimitProviderRegistration))
            ?.ImplementationInstance as AuthenticationRateLimitProviderRegistration;
        if (existing == null)
        {
            services.AddSingleton(new AuthenticationRateLimitProviderRegistration(providerName));
        }

        return services;
    }

    /// <summary>Rejects a conflicting authentication rate-limit provider without changing the service collection.</summary>
    /// <param name="services">The service collection to validate.</param>
    /// <param name="providerName">The provider name used in configuration diagnostics.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection ValidateAshlarAuthenticationRateLimitProviderMarker(
        this IServiceCollection services,
        string providerName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

        var existing = services
            .FirstOrDefault(descriptor => descriptor.ServiceType == typeof(AuthenticationRateLimitProviderRegistration))
            ?.ImplementationInstance as AuthenticationRateLimitProviderRegistration;
        if (existing != null && !string.Equals(existing.ProviderName, providerName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Multiple authentication rate-limit providers are not supported. '{existing.ProviderName}' is already registered; cannot also register '{providerName}'.");
        }

        return services;
    }

    /// <summary>Registers read-only rate-limit administration without exposing the provider repository through application DI.</summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="repositoryFactory">Creates the scoped provider-internal repository used only inside the reader.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddAshlarAuthenticationRateLimitAdministrationReader(
        this IServiceCollection services,
        Func<IServiceProvider, IAuthenticationRateLimitAdministrationReaderRepository> repositoryFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(repositoryFactory);

        services.TryAddScoped<IAuthenticationRateLimitAdministrationReader>(provider =>
            new AuthenticationRateLimitAdministrationReader(
                repositoryFactory(provider),
                provider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>(),
                provider.GetRequiredService<IAccountSecurityOperationAuthorizer>(),
                provider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>(),
                provider.GetService<TimeProvider>()));
        return services;
    }

    private sealed record AuthenticationRateLimitProviderRegistration(string ProviderName);

    /// <summary>
    /// Registers a best-effort post-commit security event handler for Ashlar security event fan-out.
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
    /// Registers a best-effort post-commit security event handler factory for Ashlar security event fan-out.
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

    internal static IServiceCollection AddProviderDurableSecurityEventFanOutHandler<THandler>(this IServiceCollection services)
        where THandler : class, IDurableSecurityEventFanOutHandler
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAshlarIdentity();
        AshlarProviderServiceCollection.TryAddProviderScoped<THandler, THandler>(services);
        services.AddScoped<IDurableSecurityEventFanOutHandler>(provider =>
            provider.GetRequiredAshlarProviderService<THandler>());
        services.AddProviderDurableTransactionParticipant<THandler>();

        return services;
    }
}
