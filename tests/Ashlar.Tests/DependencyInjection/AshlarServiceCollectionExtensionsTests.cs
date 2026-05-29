using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.DependencyInjection;

internal sealed class AshlarServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarIdentityRegistersCoreServicesWithExpectedLifetimes()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IIdentityService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<AuthenticationPipeline>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationPipeline>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationFactorPipeline>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IPrimaryAuthenticationRateLimiter, PrimaryAuthenticationRateLimiter>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationProviderRegistry, AuthenticationProviderRegistry>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ICredentialService, CredentialService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ICredentialAdministrationService, CredentialAdministrationService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationSessionService, AuthenticationSessionService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<PasswordHasherSelector>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ISecureTokenGenerator, SecureTokenGenerator>(services, ServiceLifetime.Singleton);
            AssertDescriptor<ISecureTokenHasher, Sha256TokenHasher>(services, ServiceLifetime.Singleton);
            AssertDescriptor<SecureTokenContext>(services, ServiceLifetime.Singleton);
            AssertDescriptor<ISecurityEventSink, SecurityEventFanOutSink>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IEmailSender, NullEmailSender>(services, ServiceLifetime.Singleton);
            AssertDescriptor<IdentityServiceOptions>(services, ServiceLifetime.Singleton);
            AssertDescriptor<AuthenticationSessionOptions>(services, ServiceLifetime.Singleton);
            AssertDescriptor<TimeProvider>(services, ServiceLifetime.Singleton);
            Assert.That(services.Any(d => d.ServiceType == typeof(IUserRepository)), Is.False);
        }
    }

    [Test]
    public void AddAshlarIdentityConfiguresIdentityServiceOptions()
    {
        var services = new ServiceCollection();
        var threshold = TimeSpan.FromMinutes(5);

        services.AddAshlarIdentity(options => options.LastUsedAtUpdateThreshold = threshold);

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IdentityServiceOptions>().LastUsedAtUpdateThreshold, Is.EqualTo(threshold));
    }

    [Test]
    public void AddAshlarIdentityConfiguresAuthenticationSessionOptions()
    {
        var services = new ServiceCollection();
        var lifetime = TimeSpan.FromDays(30);

        services.AddAshlarIdentity(configureSessions: options => options.DefaultLifetime = lifetime);

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<AuthenticationSessionOptions>().DefaultLifetime, Is.EqualTo(lifetime));
    }

    [Test]
    public void AddAshlarIdentityResolvesPrimaryAndFactorPipelinesToSameScopedImplementation()
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => Mock.Of<IAuthenticationProviderRegistry>());
        services.AddScoped(_ => Mock.Of<ICredentialService>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var primary = scope.ServiceProvider.GetRequiredService<IAuthenticationPipeline>();
        var factor = scope.ServiceProvider.GetRequiredService<IAuthenticationFactorPipeline>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(primary, Is.InstanceOf<AuthenticationPipeline>());
            Assert.That(factor, Is.SameAs(primary));
        }
    }

    [Test]
    public void AddAshlarIdentityConfiguresPrimaryAuthenticationRateLimitOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();
        services.Configure<PrimaryAuthenticationRateLimitOptions>(options =>
        {
            options.DefaultRule = new RateLimitRule { PermitLimit = 7, Window = TimeSpan.FromMinutes(8) };
        });

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<PrimaryAuthenticationRateLimitOptions>>().Value.DefaultRule.PermitLimit, Is.EqualTo(7));
    }

    [Test]
    public void OptionalProviderRegistrationsAcceptNullConfiguration()
    {
        var services = new ServiceCollection();

        services.AddAshlarEmailCodeSignIn();
        services.AddAshlarRecoveryCodes();
        services.AddAshlarPasswordReset();

        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IEmailCodeSignInService)));
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IRecoveryCodeService)));
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IPasswordResetService)));
    }

    [Test]
    public void AddAshlarEmailCodeSignInRegistersOptionsValidation()
    {
        var services = new ServiceCollection();

        services.AddAshlarEmailCodeSignIn(options => options.RequestRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<EmailCodeSignInOptions>>();

        var exception = Assert.Throws<OptionsValidationException>(() => _ = options.Value);
        Assert.That(exception.Failures, Does.Contain("Email code sign-in options are invalid."));
    }

    [Test]
    public void AddAshlarMagicLinkSignInRegistersOptionsValidation()
    {
        var services = new ServiceCollection();

        services.AddAshlarMagicLinkSignIn(options => options.VerificationRateLimit = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<MagicLinkSignInOptions>>();

        var exception = Assert.Throws<OptionsValidationException>(() => _ = options.Value);
        Assert.That(exception.Failures, Does.Contain("Magic-link sign-in options are invalid."));
    }

    [Test]
    public void AddAshlarIdentityConfigurationAppliesAfterProviderRegistration()
    {
        var services = new ServiceCollection();
        var threshold = TimeSpan.FromMinutes(5);

        services.AddAuthenticationProvider<LocalPasswordProvider>();
        services.AddAshlarIdentity(options => options.LastUsedAtUpdateThreshold = threshold);

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IdentityServiceOptions>().LastUsedAtUpdateThreshold, Is.EqualTo(threshold));
    }

    [Test]
    public void AddAshlarUriValidationConfiguresOptions()
    {
        var services = new ServiceCollection();
        const string allowedUri = "https://example.com/app";

        services.AddAshlarUriValidation(options => options.AllowedCallbackUris.Add(allowedUri));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<UriValidationOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IUriValidator, UriValidator>(services, ServiceLifetime.Singleton);
            Assert.That(options.AllowedCallbackUris, Contains.Item(allowedUri));
        }
    }

    [Test]
    public void AddAshlarIdentityResolvesIdentityServiceWhenRequiredDependenciesArePresent()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services
            .AddAshlarIdentity()
            .AddAuthenticationProvider<LocalPasswordProvider>()
            .AddPasswordHasher<FakePasswordHasher>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var service = scope.ServiceProvider.GetRequiredService<IIdentityService>();

        Assert.That(service, Is.TypeOf<IdentityService>());
    }

    [Test]
    public void AddAshlarPasswordResetRegistersServiceAndOptions()
    {
        var services = new ServiceCollection();
        var expiration = TimeSpan.FromMinutes(20);

        services.AddAshlarPasswordReset(options => options.Expiration = expiration);

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IPasswordResetService, PasswordResetService>(services, ServiceLifetime.Scoped);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IPasswordHasher) && descriptor.ImplementationType == typeof(PasswordHasherV1)), Is.True);
            Assert.That(provider.GetRequiredService<IOptions<PasswordResetOptions>>().Value.Expiration, Is.EqualTo(expiration));
        }
    }

    [Test]
    public void AddAshlarPasswordResetValidatesOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasswordReset(options => options.MinimumRequestDuration = TimeSpan.FromTicks(-1));

        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => _ = provider.GetRequiredService<IOptions<PasswordResetOptions>>().Value);
    }

    [Test]
    public void AddAshlarPasswordResetResolvesWhenRequiredRepositoriesArePresent()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());

        services.AddAshlarPasswordReset();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<IPasswordResetService>(), Is.TypeOf<PasswordResetService>());
    }

    [Test]
    public void AddAshlarIdentityDefaultsTimeProviderToSystem()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<TimeProvider>(), Is.SameAs(TimeProvider.System));
    }

    [Test]
    public void AddAshlarIdentityResolvesSecurityEventFanOutSinkByDefault()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
    }

    [Test]
    public void AddAshlarSecurityEventHandlerRegistersHandler()
    {
        var services = new ServiceCollection();

        services.AddAshlarSecurityEventHandler<CustomSecurityEventHandler>();

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(provider.GetServices<ISecurityEventHandler>().Single(), Is.TypeOf<CustomSecurityEventHandler>());
        }
    }

    [Test]
    public void AddAshlarSecurityEventHandlerFactoryRegistersHandler()
    {
        var services = new ServiceCollection();
        var handler = new CustomSecurityEventHandler();

        services.AddAshlarSecurityEventHandler(_ => handler);

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetServices<ISecurityEventHandler>().Single(), Is.SameAs(handler));
    }

    [Test]
    public void AddAshlarAuthorizationRegistersCoreServicesAndOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarAuthorization(options => options.MaxPermissionLength = 42);

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IAuthorizationGrantService, AuthorizationGrantService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthorizationEvaluator, AuthorizationEvaluator>(services, ServiceLifetime.Scoped);
            AssertDescriptor<AuthorizationGrantOptions>(services, ServiceLifetime.Singleton);
            Assert.That(provider.GetRequiredService<AuthorizationGrantOptions>().MaxPermissionLength, Is.EqualTo(42));
            Assert.That(services.Any(d => d.ServiceType == typeof(IAuthorizationGrantRepository)), Is.False);
        }
    }

    [Test]
    public void AddAshlarAuthorizationDoesNotOverrideCustomServices()
    {
        var services = new ServiceCollection();
        services.AddScoped<IAuthorizationGrantService, CustomAuthorizationGrantService>();

        services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<IAuthorizationGrantService>(), Is.TypeOf<CustomAuthorizationGrantService>());
    }

    [Test]
    public void AddAshlarMessagingResolvesNullEmailSenderByDefault()
    {
        var services = new ServiceCollection();
        services.AddAshlarMessaging();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IEmailSender>(), Is.TypeOf<NullEmailSender>());
    }

    [Test]
    public void AddAshlarMessagingDoesNotOverrideCustomEmailSender()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IEmailSender, CustomEmailSender>();

        services.AddAshlarMessaging();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IEmailSender>(), Is.TypeOf<CustomEmailSender>());
    }

    [Test]
    public void AddAshlarMessagingRejectsNullServices()
    {
        // ReSharper disable once NullableWarningSuppressionIsUsed
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarServiceCollectionExtensions.AddAshlarMessaging(null!));

        Assert.That(exception.ParamName, Is.EqualTo("services"));
    }

    [Test]
    public void AddAshlarIdentityResolvesDefaultTokenPrimitives()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<ISecureTokenGenerator>(), Is.TypeOf<SecureTokenGenerator>());
            Assert.That(provider.GetRequiredService<ISecureTokenHasher>(), Is.TypeOf<Sha256TokenHasher>());
            Assert.That(provider.GetRequiredService<SecureTokenContext>().Generator, Is.SameAs(provider.GetRequiredService<ISecureTokenGenerator>()));
            Assert.That(provider.GetRequiredService<SecureTokenContext>().Hasher, Is.SameAs(provider.GetRequiredService<ISecureTokenHasher>()));
        }
    }

    [Test]
    public void AddAshlarIdentityResolvesAuthenticationSessionServiceWhenRequiredDependenciesArePresent()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var service = scope.ServiceProvider.GetRequiredService<IAuthenticationSessionService>();

        Assert.That(service, Is.TypeOf<AuthenticationSessionService>());
    }

    [Test]
    public void AddAshlarMfaHandshakesPassesNotificationDependencies()
    {
        var services = new ServiceCollection();
        var userRepository = Mock.Of<IUserRepository>();
        var notificationService = Mock.Of<ISecurityNotificationService>();
        services.AddSingleton(userRepository);
        services.AddSingleton(notificationService);

        services.AddAshlarMfaHandshakes();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var dependencies = scope.ServiceProvider.GetRequiredService<AuthenticationHandshakeServiceDependencies>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(dependencies.UserRepository, Is.SameAs(userRepository));
            Assert.That(dependencies.NotificationService, Is.SameAs(notificationService));
        }
    }

    [Test]
    public void AddAuthenticationProviderRegistersNamedProvidersForRegistry()
    {
        var services = new ServiceCollection();
        services
            .AddAshlarIdentity()
            .AddAuthenticationProvider(_ => new OidcAuthenticationProvider("Google"))
            .AddAuthenticationProvider(_ => new OidcAuthenticationProvider("Microsoft"));

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var registry = scope.ServiceProvider.GetRequiredService<IAuthenticationProviderRegistry>();

        var googleAssertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Google", "google-sub", new Dictionary<string, string>());
        var microsoftAssertion = new ExternalIdentityAssertion(ProviderType.Oidc, "Microsoft", "microsoft-sub", new Dictionary<string, string>());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(registry.TryGetProvider(googleAssertion, out var google), Is.True);
            Assert.That(google, Is.TypeOf<OidcAuthenticationProvider>());
            Assert.That(registry.TryGetProvider(microsoftAssertion, out var microsoft), Is.True);
            Assert.That(microsoft, Is.TypeOf<OidcAuthenticationProvider>());
            Assert.That(registry.SupportedProviderKeys, Does.Contain(new AuthenticationProviderKey(ProviderType.Oidc, "Google")));
            Assert.That(registry.SupportedProviderKeys, Does.Contain(new AuthenticationProviderKey(ProviderType.Oidc, "Microsoft")));
        }
    }

    [Test]
    public void AddAuthenticationProviderTypeRegistrationIsIdempotent()
    {
        var services = new ServiceCollection();

        services
            .AddAshlarIdentity()
            .AddAuthenticationProvider<LocalPasswordProvider>()
            .AddAuthenticationProvider<LocalPasswordProvider>();

        var providerRegistrations = services.Where(descriptor =>
            descriptor.ServiceType == typeof(IAuthenticationProvider)
            && descriptor.ImplementationType == typeof(LocalPasswordProvider));

        Assert.That(providerRegistrations, Has.Exactly(1).Items);
    }

    [Test]
    public void AddPasswordHasherRegistersHashersForSelector()
    {
        var services = new ServiceCollection();
        services
            .AddAshlarIdentity()
            .AddPasswordHasher<FakePasswordHasher>()
            .AddPasswordHasher(_ => new FakePasswordHasher { Version = 0x02 });

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var selector = scope.ServiceProvider.GetRequiredService<PasswordHasherSelector>();

        Assert.That(selector.DefaultHasher.Version, Is.EqualTo(0x02));
    }

    [Test]
    public void AddPasswordHasherTypeRegistrationIsIdempotent()
    {
        var services = new ServiceCollection();

        services
            .AddAshlarIdentity()
            .AddPasswordHasher<FakePasswordHasher>()
            .AddPasswordHasher<FakePasswordHasher>();

        var hasherRegistrations = services.Where(descriptor =>
            descriptor.ServiceType == typeof(IPasswordHasher)
            && descriptor.ImplementationType == typeof(FakePasswordHasher));

        Assert.That(hasherRegistrations, Has.Exactly(1).Items);
    }

    [Test]
    public void LocalPasswordProviderRequiresAtLeastOnePasswordHasher()
    {
        var services = new ServiceCollection();
        services
            .AddAshlarIdentity()
            .AddAuthenticationProvider<LocalPasswordProvider>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var exception = Assert.Throws<ArgumentException>(() =>
            scope.ServiceProvider.GetRequiredService<IEnumerable<IAuthenticationProvider>>());

        Assert.That(exception.Message, Does.Contain("At least one password hasher"));
    }

    [Test]
    public void MissingUserRepositoryFailsThroughServiceResolution()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            scope.ServiceProvider.GetRequiredService<IIdentityService>());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(exception.Message, Does.Contain(nameof(IUserRepository)));
            Assert.That(exception.Message, Does.Contain("No service for type"));
        }
    }

    private static void AssertDescriptor<TService, TImplementation>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.ImplementationType == typeof(TImplementation)
            && descriptor.Lifetime == lifetime));
    }

    private static void AssertDescriptor<TService>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.Lifetime == lifetime));
    }

    private sealed class CustomEmailSender : IEmailSender
    {
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class CustomSecurityEventHandler : ISecurityEventHandler
    {
        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class CustomAuthorizationGrantService : IAuthorizationGrantService
    {
        public Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<bool> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<AuthorizationGrant>> ListGrantsAsync(ListAuthorizationGrantsRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    [Test]
    public void AddAshlarEmailVerificationRegistersService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddAshlarEmailVerification();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<IEmailVerificationService>(), Is.TypeOf<EmailVerificationService>());
    }

    [Test]
    public void AddAshlarEmailVerificationAppliesConfiguration()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddAshlarEmailVerification(options => options.Subject = "Verify custom");

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<EmailVerificationOptions>>().Value.Subject, Is.EqualTo("Verify custom"));
    }

    [Test]
    public void AddAshlarEmailVerificationRegistersOptionsValidation()
    {
        var services = new ServiceCollection();

        services.AddAshlarEmailVerification(options => options.RequestRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<EmailVerificationOptions>>();

        var exception = Assert.Throws<OptionsValidationException>(() => _ = options.Value);
        Assert.That(exception.Failures, Does.Contain("Email verification options are invalid."));
    }

    [Test]
    public void AddAshlarEmailChangeRegistersService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarEmailChange();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<IEmailChangeService>(), Is.TypeOf<EmailChangeService>());
    }

    [Test]
    public void AddAshlarEmailChangeAppliesConfiguration()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarEmailChange(options => options.Subject = "Change custom");

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<EmailChangeOptions>>().Value.Subject, Is.EqualTo("Change custom"));
    }

    [Test]
    public void AddAshlarEmailChangeRegistersOptionsValidation()
    {
        var services = new ServiceCollection();

        services.AddAshlarEmailChange(options => options.VerificationRateLimit = new RateLimitRule { PermitLimit = 1, Window = TimeSpan.Zero });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<EmailChangeOptions>>();

        var exception = Assert.Throws<OptionsValidationException>(() => _ = options.Value);
        Assert.That(exception.Failures, Does.Contain("Email change options are invalid."));
    }

    [Test]
    public void AddAshlarSecurityNotificationsRegistersService()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityNotifications();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityNotificationService>(), Is.TypeOf<SecurityNotificationService>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityNotificationSuppressionStore>(), Is.TypeOf<InMemorySecurityNotificationSuppressionStore>());
        }
    }

    [Test]
    public void AddAshlarSecurityNotificationsAppliesConfiguration()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityNotifications(options => options.Enabled = true);

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<SecurityNotificationOptions>>().Value.Enabled, Is.True);
    }
}
