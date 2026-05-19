using Ashlar.Identity;
using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Authorization.Models;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.External;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Security.Tokens;
using Ashlar.Tests.Identity;
using Microsoft.AspNetCore.DataProtection;
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
            AssertDescriptor<IAuthenticationPipeline, AuthenticationPipeline>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationProviderRegistry, AuthenticationProviderRegistry>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ICredentialService, CredentialService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<IAuthenticationSessionService, AuthenticationSessionService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<PasswordHasherSelector>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ISecureTokenGenerator, SecureTokenGenerator>(services, ServiceLifetime.Singleton);
            AssertDescriptor<ISecureTokenHasher, Sha256TokenHasher>(services, ServiceLifetime.Singleton);
            AssertDescriptor<SecureTokenContext>(services, ServiceLifetime.Singleton);
            AssertDescriptor<IEmailSender, NullEmailSender>(services, ServiceLifetime.Singleton);
            AssertDescriptor<IdentityServiceOptions>(services, ServiceLifetime.Singleton);
            AssertDescriptor<AuthenticationSessionOptions>(services, ServiceLifetime.Singleton);
            AssertDescriptor<TimeProvider>(services, ServiceLifetime.Singleton);
            Assert.That(services.Any(d => d.ServiceType == typeof(IIdentityRepository)), Is.False);
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
    public void OptionalProviderRegistrationsAcceptNullConfiguration()
    {
        var services = new ServiceCollection();

        services.AddAshlarEmailCodeSignIn();
        services.AddAshlarRecoveryCodes();

        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IEmailCodeSignInService)));
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(IRecoveryCodeService)));
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
        services.AddSingleton(Mock.Of<IIdentityRepository>());
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
    public void AddAshlarIdentityDefaultsTimeProviderToSystem()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<TimeProvider>(), Is.SameAs(TimeProvider.System));
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
        var identityRepository = Mock.Of<IIdentityRepository>();
        var notificationService = Mock.Of<ISecurityNotificationService>();
        services.AddSingleton(identityRepository);
        services.AddSingleton(notificationService);

        services.AddAshlarMfaHandshakes();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var dependencies = scope.ServiceProvider.GetRequiredService<AuthenticationHandshakeServiceDependencies>();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(dependencies.IdentityRepository, Is.SameAs(identityRepository));
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
    public void MissingIdentityRepositoryFailsThroughServiceResolution()
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
            Assert.That(exception.Message, Does.Contain(nameof(IIdentityRepository)));
            Assert.That(exception.Message, Does.Contain("No service for type"));
        }
    }

    [Test]
    public void AddAshlarDataProtectionSecretProtectorRegistersSecretProtectorWhenDataProtectionProviderIsConfigured()
    {
        var dataProtectionProvider = new Mock<IDataProtectionProvider>();
        var dataProtector = new Mock<IDataProtector>();
        dataProtectionProvider
            .Setup(provider => provider.CreateProtector("Ashlar.Identity.Credentials"))
            .Returns(dataProtector.Object);

        var services = new ServiceCollection();
        services.AddSingleton(dataProtectionProvider.Object);
        services.AddAshlarDataProtectionSecretProtector();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();

        Assert.That(protector, Is.TypeOf<DataProtectionSecretProtector>());
    }

    [Test]
    public void AddAshlarDataProtectionSecretProtectorRegistersCoreIdentityServices()
    {
        var services = new ServiceCollection();

        services.AddAshlarDataProtectionSecretProtector();

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IIdentityService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ICredentialService, CredentialService>(services, ServiceLifetime.Scoped);
            AssertDescriptor<ISecretProtector, DataProtectionSecretProtector>(services, ServiceLifetime.Scoped);
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
        services.AddSingleton(Mock.Of<IIdentityRepository>());
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
        services.AddSingleton(Mock.Of<IIdentityRepository>());
        services.AddAshlarEmailVerification(options => options.Subject = "Verify custom");

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<EmailVerificationOptions>>().Value.Subject, Is.EqualTo("Verify custom"));
    }

    [Test]
    public void AddAshlarEmailChangeRegistersService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IIdentityRepository>());
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
        services.AddSingleton(Mock.Of<IIdentityRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarEmailChange(options => options.Subject = "Change custom");

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IOptions<EmailChangeOptions>>().Value.Subject, Is.EqualTo("Change custom"));
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
