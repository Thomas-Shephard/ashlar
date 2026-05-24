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
    /// <param name="services">The services value.</param>
    /// <param name="configure">The configure value.</param>
    /// <param name="configureSessions">The configure sessions value.</param>
    /// <returns>The service collection.</returns>
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
            provider.GetService<IMfaPolicyEvaluator>()));
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
            provider.GetService<IIdentityRepository>(),
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
        services.TryAddSingleton<ISecurityEventSink, NullSecurityEventSink>();
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
}
