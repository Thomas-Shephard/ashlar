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
    /// This method intentionally does not register <see cref="IUserRepository"/> or <see cref="ICredentialRepository"/> or
    /// <see cref="ISecretProtector"/>. Applications should provide those dependencies explicitly.
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
            .Validate(PrimaryAuthenticationRateLimitOptions.Validate, "Primary authentication rate-limit options are invalid.");
        services.AddOptions<AuthenticationFactorRateLimitOptions>()
            .Validate(AuthenticationFactorRateLimitOptions.Validate, "Secondary factor rate-limit options are invalid.");

        services.TryAdd(new ServiceDescriptor(
            typeof(IIdentityService),
            provider => new IdentityService(
                provider.GetRequiredService<IUserRepository>(),
                provider.GetRequiredService<IAuthenticationProviderRegistry>(),
                provider.GetRequiredService<ICredentialService>(),
                provider.GetRequiredService<IAuthenticationPipeline>(),
                provider.GetRequiredService<IAshlarTransactionProvider>(),
                provider.GetService<ISecurityEventSink>(),
                provider.GetService<TimeProvider>(),
                provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>()),
            ServiceLifetime.Scoped));
        services.TryAddScoped<AuthenticationPipeline>();
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
            provider.GetService<IAuthenticationProviderRegistry>()));
        services.TryAddScoped<IAccountSecurityGuard, AllowAccountSecurityGuard>();
        services.TryAddScoped<IAccountSecurityService, AccountSecurityService>();
        services.TryAddScoped<IUserAdministrationService, UserAdministrationService>();
        services.TryAddScoped<ICredentialAdministrationService, CredentialAdministrationService>();
        services.TryAddScoped<ISecurityEventAdministrationService, SecurityEventAdministrationService>();
        services.TryAddScoped<IAuthenticationSessionAdministrationService, AuthenticationSessionAdministrationService>();
        services.TryAddScoped(provider => new AuthenticationSessionServiceDependencies(
            provider.GetService<AuthenticationSessionOptions>(),
            provider.GetService<TimeProvider>(),
            provider.GetService<ISecurityEventSink>(),
            provider.GetService<IUserRepository>(),
            provider.GetService<ISecurityNotificationService>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILogger<AuthenticationSessionService>>(),
            provider.GetService<global::Microsoft.Extensions.Logging.ILoggerFactory>()));
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
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<IdentityServiceOptions>>().Value);
        services.TryAddSingleton(provider => provider.GetRequiredService<IOptions<AuthenticationSessionOptions>>().Value);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IAshlarTransactionProvider, NullTransactionProvider>();
        services.AddAshlarUriValidation();

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
