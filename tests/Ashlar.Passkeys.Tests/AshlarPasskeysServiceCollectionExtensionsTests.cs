using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ashlar.Passkeys.Tests;

internal sealed class AshlarPasskeysServiceCollectionExtensionsTests
{
    [Test]
    public void AddAshlarPasskeysRegistersServicesAndAppliesOptions()
    {
        var services = new ServiceCollection();

        services.AddAshlarPasskeys(options =>
        {
            options.Origin = "https://example.com";
            options.RelyingPartyId = "example.com";
        });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<PasskeyOptions>>().Value;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(options.RelyingPartyId, Is.EqualTo("example.com"));
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IAuthenticationProvider) && descriptor.ImplementationType == typeof(PasskeyAuthenticationProvider)), Is.True);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IPasskeyCeremonyValidator) && descriptor.ImplementationType == typeof(Fido2PasskeyCeremonyValidator)), Is.True);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IPasskeyService) && descriptor.ImplementationType == typeof(PasskeyService)), Is.True);
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
            Assert.That(services.Where(descriptor => descriptor.ServiceType == typeof(IPasskeyService) && descriptor.ImplementationType == typeof(PasskeyService)), Has.Exactly(1).Items);
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

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("unexpected")]
    public void PasskeyOptionsShouldRejectInvalidUserVerification(string userVerification)
    {
        var options = new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", UserVerification = userVerification };

        Assert.That(PasskeyOptions.Validate(options), Is.False);
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("unexpected")]
    public void PasskeyOptionsShouldRejectInvalidAttestation(string attestation)
    {
        var options = new PasskeyOptions { Origin = "https://example.com", RelyingPartyId = "example.com", Attestation = attestation };

        Assert.That(PasskeyOptions.Validate(options), Is.False);
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

        public string CreateAuthenticationOptions(PasskeyOptions options, string challenge, IReadOnlyList<UserCredential> allowedCredentials)
        {
            throw new NotSupportedException();
        }

        public Task<PasskeyAuthenticationVerificationResult> VerifyAuthenticationAsync(PasskeyOptions options, PasskeyChallenge challenge, UserCredential credential, JsonElement assertionResponse, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}


