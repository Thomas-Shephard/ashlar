using System.Text.Json;
using Ashlar.Auditing;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Operational.Configuration;
using Ashlar.Security.Encryption;
using Ashlar.Security.Hashing;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Passkeys.Tests;

internal sealed class AshlarPasskeysServiceCollectionExtensionsTests
{
    [Test]
    public void PasskeysAssemblyDoesNotReferenceProviderContracts()
    {
        Assert.That(typeof(Fido2PasskeyCeremonyValidator).Assembly.GetReferencedAssemblies().Select(name => name.Name),
            Does.Not.Contain("Ashlar.ProviderContracts"));
    }

    [Test]
    public void AddAshlarPasskeysRegistersServicesAndAppliesOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasskeys(options =>
        {
            options.Origin = "https://example.com";
            options.RelyingPartyId = "example.com";
        });
        services.AddAshlarNoMfaPolicy();

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PasskeyOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.RelyingPartyId, Is.EqualTo("example.com"));
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IAuthenticationProvider) && descriptor.ImplementationType == typeof(PasskeyAuthenticationProvider)), Is.True);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IPasskeyCeremonyValidator) && descriptor.Lifetime == ServiceLifetime.Scoped), Is.True);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IPasskeyService) && descriptor.Lifetime == ServiceLifetime.Scoped), Is.True);
        }
    }

    [Test]
    public void AddAshlarPasskeysValidatesOptionsOnStart()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasskeys(options =>
        {
            options.Origin = "https://example.com";
            options.RelyingPartyId = "evil.test";
        });

        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
        Assert.That(exception?.OptionsType, Is.EqualTo(typeof(PasskeyOptions)));
    }

    [Test]
    public void CorePasskeyCompositionBuildsWithStrictValidation()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationHandshakeRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IPasskeyChallengeRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IPersistentSecurityEventSink>());
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>("Test");
        services.AddAshlarDurableTransactionParticipant<IUserRepository>();
        services.AddAshlarDurableTransactionParticipant<ICredentialRepository>();
        services.AddAshlarDurableTransactionParticipant<IAuthenticationSessionRepository>();
        services.AddAshlarDurableTransactionParticipant<IPasskeyChallengeRepository>();
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        services.AddPermissiveAccountSecurityGuard();
        services.AddPasswordHasher<PasswordHasherV1>();
        services.AddAshlarPasskeys(options =>
        {
            options.Origin = "https://example.com";
            options.RelyingPartyId = "example.com";
        });
        services.AddAshlarNoMfaPolicy();

        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IPasskeyService),
            typeof(IPasskeyCeremonyValidator),
            typeof(IAuthenticationOrchestrator),
            typeof(IAuthenticationHandshakeService));
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<IPasskeyService>(), Is.Not.Null);
            Assert.That(scope.ServiceProvider.GetServices<IAuthenticationProvider>().Any(x => x.GetType().Name == "PasskeyAuthenticationProvider"), Is.True);
        }
    }

    [Test]
    public void AddAshlarPasskeysDoesNotOverrideCustomCeremonyValidator()
    {
        var services = new ServiceCollection();
        services.AddScoped<IPasskeyCeremonyValidator, StubPasskeyCeremonyValidator>();

        services.AddAshlarPasskeys();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(IPasskeyCeremonyValidator)), Has.Exactly(1).Items);
            Assert.That(services.Single(descriptor => descriptor.ServiceType == typeof(IPasskeyCeremonyValidator)).ImplementationType, Is.EqualTo(typeof(StubPasskeyCeremonyValidator)));
        }
    }

    [Test]
    public void AddAshlarPasskeysIsIdempotentForProviderAndServiceRegistrations()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasskeys();
        services.AddAshlarPasskeys();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(IAuthenticationProvider) && descriptor.ImplementationType == typeof(PasskeyAuthenticationProvider)), Has.Exactly(1).Items);
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(IPasskeyService)), Has.Exactly(1).Items);
        }
    }

    [Test]
    public async Task AddAshlarPasskeysReportsMissingChallengeRepository()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasskeys();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues, Has.Some.Matches<AshlarConfigurationIssue>(issue =>
            issue.Code == AshlarConfigurationIssueCodes.PasskeyChallengeRepositoryMissing
            && issue.Severity == AshlarConfigurationIssueSeverity.Error));
    }

    [Test]
    public void AddAshlarPasskeysRegistersConfigurationValidator()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasskeys();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IAshlarConfigurationValidator>(), Is.Not.Null);
    }

    [Test]
    public async Task AddAshlarPasskeysDoesNotReportChallengeRepositoryWhenRegistered()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped<IPasskeyChallengeRepository>(_ => new StubPasskeyChallengeRepository());

        services.AddAshlarPasskeys();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.IsAshlarProviderServiceRegistered<IPasskeyChallengeRepository>(), Is.True);
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.PasskeyChallengeRepositoryMissing));
        }
    }

    [Test]
    public async Task AddAshlarPasskeysRejectsOrdinaryChallengeRepositoryRegistration()
    {
        var services = new ServiceCollection();
        services.AddScoped<IPasskeyChallengeRepository, StubPasskeyChallengeRepository>();
        services.AddAshlarPasskeys();

        using var provider = services.BuildServiceProvider();
        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Contains.Item(AshlarConfigurationIssueCodes.PasskeyChallengeRepositoryMissing));
    }

    [Test]
    public void ProviderRegistrationInspectionRejectsOrdinaryFallbackServices()
    {
        var provider = new FallbackServiceProvider(typeof(IPasskeyChallengeRepository), new StubPasskeyChallengeRepository());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.IsAshlarProviderServiceRegistered<IPasskeyChallengeRepository>(), Is.False);
            Assert.That(provider.IsAshlarProviderServiceRegistered<IPasskeyService>(), Is.False);
        }
    }

    [TestCase("https://example.com/callback", "example.com")]
    [TestCase("https://user@example.com", "example.com")]
    [TestCase("https://example.com?x=1", "example.com")]
    [TestCase("https://example.com", "https://example.com")]
    [TestCase("https://example.com", "example.com/path")]
    [TestCase("https://example.com", "example.com:443")]
    [TestCase("https://evil.com", "example.com")]
    [TestCase("ftp://example.com", "example.com")]
    [TestCase("http://example.com", "example.com")]
    [TestCase("https://example.com", null)]
    [TestCase("https://example.com", " ")]
    public void PasskeyOptionsShouldRejectInvalidOriginOrRelyingPartyConfiguration(string origin, string? relyingPartyId)
    {
        var options = new PasskeyOptions { Origin = origin, RelyingPartyId = relyingPartyId! };

        Assert.That(PasskeyOptions.Validate(options), Is.False);
    }

    [TestCase("user", "Passkey user persistence must be the exact instance enlisted in the durable transaction composition; DI decorators must be composed inside the persistence provider boundary.")]
    [TestCase("credential", "Passkey credential persistence must be the exact instance enlisted in the durable transaction composition; DI decorators must be composed inside the persistence provider boundary.")]
    [TestCase("challenge", "Passkey challenge persistence must be the exact instance enlisted in the durable transaction composition; DI decorators must be composed inside the persistence provider boundary.")]
    [TestCase("session", "Passkey session persistence must be the exact instance enlisted in the durable transaction composition; DI decorators must be composed inside the persistence provider boundary.")]
    [TestCase("audit", "Persistent security event storage and durable fan-out handlers must be the exact instances enlisted in the durable transaction composition. DI decorators must be composed by the persistence provider rather than applied outside its transaction boundary.")]
    [TestCase("fanout", "Persistent security event storage and durable fan-out handlers must be the exact instances enlisted in the durable transaction composition. DI decorators must be composed by the persistence provider rather than applied outside its transaction boundary.")]
    public void CorePasskeyCompositionRejectsMissingDurableParticipant(string omitted, string expectedMessage)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<ICredentialRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationHandshakeRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IPasskeyChallengeRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IPersistentSecurityEventSink>());
        if (omitted == "fanout") services.AddScoped(_ => Mock.Of<IDurableSecurityEventFanOutHandler>());
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>("Test");
        if (omitted != "user") services.AddAshlarDurableTransactionParticipant<IUserRepository>();
        if (omitted != "credential") services.AddAshlarDurableTransactionParticipant<ICredentialRepository>();
        if (omitted != "challenge") services.AddAshlarDurableTransactionParticipant<IPasskeyChallengeRepository>();
        if (omitted != "session") services.AddAshlarDurableTransactionParticipant<IAuthenticationSessionRepository>();
        if (omitted != "audit") services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        services.AddAshlarPasskeys();
        services.AddAshlarNoMfaPolicy();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var exception = Assert.Throws<InvalidOperationException>(() => scope.ServiceProvider.GetRequiredService<IPasskeyService>());
        Assert.That(exception?.Message, Is.EqualTo(expectedMessage));
    }

    [Test]
    public void PasskeyOptionsShouldRejectBlankProviderName()
    {
        var options = new PasskeyOptions { ProviderName = " " };

        Assert.That(PasskeyOptions.Validate(options), Is.False);
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("unexpected")]
    public void PasskeyOptionsShouldRejectInvalidUserVerification(string userVerification)
    {
        var registration = new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", RegistrationUserVerification = userVerification };
        var authentication = new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", AuthenticationUserVerification = userVerification };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(PasskeyOptions.Validate(registration), Is.False);
            Assert.That(PasskeyOptions.Validate(authentication), Is.False);
        }
    }

    [Test]
    public void PasskeyOptionsShouldUseUserVerificationDefaults()
    {
        var options = new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com" };

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.RegistrationUserVerification, Is.EqualTo(PasskeyUserVerificationRequirement.Preferred));
            Assert.That(options.AuthenticationUserVerification, Is.EqualTo(PasskeyUserVerificationRequirement.Preferred));
            Assert.That(PasskeyOptions.Validate(options), Is.True);
        }
    }

    [Test]
    public void PasskeyUserVerificationRequirementShouldExposeWebAuthnValues()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.That(PasskeyUserVerificationRequirement.Required, Is.EqualTo("required"));
            Assert.That(PasskeyUserVerificationRequirement.Preferred, Is.EqualTo("preferred"));
            Assert.That(PasskeyUserVerificationRequirement.Discouraged, Is.EqualTo("discouraged"));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("unexpected")]
    public void PasskeyOptionsShouldRejectInvalidAttestation(string attestation)
    {
        var options = new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", AttestationConveyancePreference = attestation };

        Assert.That(PasskeyOptions.Validate(options), Is.False);
    }

    [Test]
    public void PasskeyOptionsShouldRejectInvalidAuthenticationChallengeStartRateLimit()
    {
        var options = new PasskeyOptions
        {
            Origin = "https://example.com",
            RelyingPartyId = "example.com",
            AuthenticationChallengeStartRateLimit = new RateLimitRule { PermitLimit = 0, Window = TimeSpan.FromMinutes(1) }
        };

        Assert.That(PasskeyOptions.Validate(options), Is.False);
    }

    [Test]
    public void PasskeyOptionsShouldRejectNullOptions()
    {
        Assert.That(PasskeyOptions.Validate(null), Is.False);
    }

    [TestCase("https://login.example.com", "example.com")]
    [TestCase("http://localhost:5000", "localhost")]
    [TestCase("http://127.0.0.1:5000", "127.0.0.1")]
    public void PasskeyOptionsShouldAcceptValidOriginAndRelyingPartyConfiguration(string origin, string relyingPartyId)
    {
        var options = new PasskeyOptions { Origin = origin, RelyingPartyId = relyingPartyId };

        Assert.That(PasskeyOptions.Validate(options), Is.True);
    }

    private sealed class StubPasskeyCeremonyValidator : IPasskeyCeremonyValidator
    {
        public string CreateRegistrationOptions(PasskeyOptions options, IUser user, string displayName, string challenge, IReadOnlyList<UserCredential> existingCredentials)
        {
            throw new NotSupportedException();
        }

        public Task<PasskeyRegistrationVerificationResult> VerifyRegistrationAsync(PasskeyOptions options, PasskeyChallenge challenge, JsonElement credentialResponse, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public string CreateAuthenticationOptions(PasskeyOptions options, string challenge, IReadOnlyList<UserCredential> allowedCredentials, string userVerification)
        {
            throw new NotSupportedException();
        }

        public Task<PasskeyAuthenticationVerificationResult> VerifyAuthenticationAsync(PasskeyOptions options, PasskeyChallenge challenge, UserCredential credential, JsonElement assertionResponse, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class StubPasskeyChallengeRepository : IPasskeyChallengeRepository
    {
        public Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class FallbackServiceProvider(Type serviceType, object service) : IServiceProvider
    {
        public object? GetService(Type requestedServiceType)
        {
            return requestedServiceType == serviceType ? service : null;
        }
    }
}
