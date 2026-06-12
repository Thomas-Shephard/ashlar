using Ashlar.AspNetCore.Security.Encryption;
using Ashlar.AspNetCore.Sessions;
using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Ashlar.Testing.DependencyInjection;
using Ashlar.Identity.Features.Credentials;
using Ashlar.Security.Encryption;
using Ashlar.AspNetCore.Authorization;
using Ashlar.AspNetCore.Mfa;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.AspNetCore.Tests;

internal sealed class AshlarAspNetCoreServiceCollectionExtensionsTests
{
    [Test]
    public void AshlarPermissionRequirementShouldNormalizePermission()
    {
        var requirement = new AshlarPermissionRequirement("Read.Posts", "MyPolicy");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement.Permission, Is.EqualTo("read.posts"));
            Assert.That(requirement.PolicyName, Is.EqualTo("MyPolicy"));
        }
    }

    [Test]
    public void AshlarRoleRequirementShouldNormalizeRole()
    {
        var requirement = new AshlarRoleRequirement("Admin", "MyPolicy");
        using (Assert.EnterMultipleScope())
        {
            Assert.That(requirement.Role, Is.EqualTo("admin"));
            Assert.That(requirement.PolicyName, Is.EqualTo("MyPolicy"));
        }
    }

    [Test]
    public void AddAshlarAspNetCoreAuthorizationShouldRegisterPoliciesAndScopes()
    {
        var services = new ServiceCollection();
        services.AddLogging(); // Required by some auth components
        services.AddAshlarAspNetCoreAuthorization(options =>
        {
            options.AddPermissionPolicy("EditPost", "posts:edit", scope =>
            {
                scope.ScopeType = "post";
                scope.ScopeIdRouteValueName = "postId";
            });
            options.AddRolePolicy("Manager", "manager");
        });

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AshlarAuthorizationOptions>>().Value;

        Assert.That(options.PolicyScopes, Has.Count.EqualTo(1));
        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.PolicyScopes["EditPost"].ScopeType, Is.EqualTo("post"));
            Assert.That(options.PolicyScopes["EditPost"].ScopeIdRouteValueName, Is.EqualTo("postId"));
        }
    }

    [Test]
    public void AddAshlarAspNetCoreAuthorizationShouldAcceptNullConfiguration()
    {
        var services = new ServiceCollection();

        services.AddAshlarAspNetCoreAuthorization();

        using var provider = services.BuildServiceProvider();
        Assert.That(provider.GetRequiredService<IOptions<AshlarAuthorizationOptions>>().Value, Is.Not.Null);
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldRejectHostPrefixedCookieWithDomain()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.Cookie.Domain = "example.com";
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldRejectHostPrefixedCookieWithNonRootPath()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.Cookie.Path = "/app";
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldRejectHostPrefixedCookieWithoutAlwaysSecurePolicy()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentException>(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreSessionsShouldAllowNonHostPrefixedCookieCustomization()
    {
        var services = new ServiceCollection();

        Assert.DoesNotThrow(() => services.AddAshlarAspNetCoreSessions(options =>
        {
            options.CookieName = "Ashlar.Session";
            options.Cookie.Domain = "example.com";
            options.Cookie.Path = "/app";
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        }));
    }

    [Test]
    public void AddAshlarAspNetCoreRememberedMfaDeviceCookiesShouldRegisterManagerAndOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarAspNetCoreRememberedMfaDeviceCookies(options =>
        {
            options.CookieName = "Ashlar.RememberedMfaDevice";
            options.Cookie.Path = "/app";
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IAshlarRememberedMfaDeviceCookieManager, AshlarRememberedMfaDeviceCookieManager>(services, ServiceLifetime.Scoped);
            Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor => descriptor.ServiceType == typeof(IConfigureOptions<AshlarRememberedMfaDeviceCookieOptions>)));
        }

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AshlarRememberedMfaDeviceCookieOptions>>().Value;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.CookieName, Is.EqualTo("Ashlar.RememberedMfaDevice"));
            Assert.That(options.Cookie.Path, Is.EqualTo("/app"));
            Assert.That(options.Cookie.SecurePolicy, Is.EqualTo(CookieSecurePolicy.SameAsRequest));
        }
    }

    [Test]
    public void AddAshlarAspNetCoreRememberedMfaDeviceCookiesShouldUseStandardOptionsPipeline()
    {
        var services = new ServiceCollection();

        services.AddAshlarAspNetCoreRememberedMfaDeviceCookies();
        services.Configure<AshlarRememberedMfaDeviceCookieOptions>(options => options.CookieName = "Ashlar.RememberedMfaDevice");

        using (Assert.EnterMultipleScope())
        {
            AssertDescriptor<IAshlarRememberedMfaDeviceCookieManager, AshlarRememberedMfaDeviceCookieManager>(services, ServiceLifetime.Scoped);
            Assert.That(services, Has.None.Matches<ServiceDescriptor>(descriptor =>
                descriptor.ServiceType == typeof(IOptions<AshlarRememberedMfaDeviceCookieOptions>) &&
                descriptor.ImplementationInstance != null));
        }

        using var provider = services.BuildServiceProvider();
        Assert.That(provider.GetRequiredService<IOptions<AshlarRememberedMfaDeviceCookieOptions>>().Value.CookieName, Is.EqualTo("Ashlar.RememberedMfaDevice"));
    }

    [Test]
    public void AddAshlarAspNetCoreRememberedMfaDeviceCookiesShouldResolveSecureDefaults()
    {
        var services = new ServiceCollection();

        services.AddAshlarAspNetCoreRememberedMfaDeviceCookies();

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AshlarRememberedMfaDeviceCookieOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.CookieName, Is.EqualTo(AshlarRememberedMfaDeviceCookieDefaults.CookieName));
            Assert.That(options.Cookie.SecurePolicy, Is.EqualTo(CookieSecurePolicy.Always));
        }
    }

    [Test]
    public void AddAshlarAspNetCoreRememberedMfaDeviceCookiesShouldRejectInvalidHostCookieOptions()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => AshlarAspNetCoreServiceCollectionExtensions.AddAshlarAspNetCoreRememberedMfaDeviceCookies(null!));
            Assert.Throws<ArgumentException>(() => ResolveRememberedMfaDeviceCookieOptions(options => options.CookieName = " "));
            Assert.Throws<ArgumentException>(() => ResolveRememberedMfaDeviceCookieOptions(options => options.Cookie.Domain = "example.com"));
            Assert.Throws<ArgumentException>(() => ResolveRememberedMfaDeviceCookieOptions(options => options.Cookie.Path = "/app"));
            Assert.Throws<ArgumentException>(() => ResolveRememberedMfaDeviceCookieOptions(options => options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest));
            Assert.DoesNotThrow(() => new ServiceCollection().AddAshlarAspNetCoreRememberedMfaDeviceCookies(options =>
            {
                options.CookieName = "Ashlar.RememberedMfaDevice";
                options.Cookie.Domain = "example.com";
                options.Cookie.Path = "/app";
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            }));
        }
    }

    [Test]
    public void AddAshlarDataProtectionSecretProtectorRegistersSecretProtectorWhenDataProtectionProviderIsConfigured()
    {
        var dataProtectionProvider = new Mock<IDataProtectionProvider>();
        var dataProtector = new Mock<IDataProtector>();
        dataProtectionProvider
            .Setup(provider => provider.CreateProtector("Ashlar.Identity.Features.Credentials"))
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

    [Test]
    public void AddAshlarDataProtectionSecretProtectorPreservesConfiguredLifetime()
    {
        var services = new ServiceCollection();

        services.AddAshlarDataProtectionSecretProtector(ServiceLifetime.Singleton);

        AssertDescriptor<ISecretProtector, DataProtectionSecretProtector>(services, ServiceLifetime.Singleton);
    }

    [Test]
    public void CoreAspNetCoreSessionAndAuthorizationCompositionBuildsWithStrictValidation()
    {
        var secretProtector = new Mock<ISecretProtector>().Object;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddSingleton(Mock.Of<IAuthorizationGrantRepository>());
        services.AddSingleton<ISecretProtector>(secretProtector);
        services.AddAshlarIdentity();
        services.AddAshlarAuthorization();
        services.AddAshlarDataProtectionSecretProtector();
        services.AddAshlarAspNetCoreSessions();
        services.AddAshlarAspNetCoreAuthorization(options => options.RequireFreshMfa());

        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IIdentityService),
            typeof(IAshlarSignInManager),
            typeof(IAuthorizationService));
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecretProtector>(), Is.SameAs(secretProtector));
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarSignInManager>(), Is.TypeOf<AshlarSignInManager>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IEnumerable<IAuthorizationHandler>>(), Has.Some.TypeOf<AshlarAuthorizationHandler>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IEnumerable<IAuthorizationHandler>>(), Has.Some.TypeOf<AshlarStepUpAuthorizationHandler>());
        }
    }

    private static void AssertDescriptor<TService, TImplementation>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.ImplementationType == typeof(TImplementation)
            && descriptor.Lifetime == lifetime));
    }

    private static AshlarRememberedMfaDeviceCookieOptions ResolveRememberedMfaDeviceCookieOptions(Action<AshlarRememberedMfaDeviceCookieOptions> configure)
    {
        var services = new ServiceCollection();
        services.AddAshlarAspNetCoreRememberedMfaDeviceCookies(configure);
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<AshlarRememberedMfaDeviceCookieOptions>>().Value;
    }

    private static void AssertDescriptor<TService>(IServiceCollection services, ServiceLifetime lifetime)
    {
        Assert.That(services, Has.Some.Matches<ServiceDescriptor>(descriptor =>
            descriptor.ServiceType == typeof(TService)
            && descriptor.Lifetime == lifetime));
    }
}
