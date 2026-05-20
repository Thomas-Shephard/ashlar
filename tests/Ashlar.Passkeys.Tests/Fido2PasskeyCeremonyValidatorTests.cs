using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Moq;

namespace Ashlar.Passkeys.Tests;

[TestFixture]
internal sealed class Fido2PasskeyCeremonyValidatorTests
{
    private static readonly string[] ExpectedTransports = ["usb", "internal"];
    private static readonly string[] ExpectedVerifiedTransports = ["Usb", "Internal"];

    [Test]
    public void ConstructorShouldRejectNullRepository()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new Fido2PasskeyCeremonyValidator(null!));
    }

    [Test]
    public void ConstructorShouldRejectNullTestDelegates()
    {
        var repository = new Mock<IIdentityRepository>().Object;
        Func<Fido2NetLib.Fido2, MakeNewCredentialParams, CancellationToken, Task<RegisteredPublicKeyCredential>> makeCredential = (_, _, _) => Task.FromResult(new RegisteredPublicKeyCredential());
        Func<Fido2NetLib.Fido2, MakeAssertionParams, CancellationToken, Task<VerifyAssertionResult>> makeAssertion = (_, _, _) => Task.FromResult(new VerifyAssertionResult());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new Fido2PasskeyCeremonyValidator(repository, null!, makeAssertion));
            Assert.Throws<ArgumentNullException>(() => _ = new Fido2PasskeyCeremonyValidator(repository, makeCredential, null!));
        }
    }

    [Test]
    public void CreateRegistrationOptionsShouldUseAshlarChallengeAndConfiguredRelyingParty()
    {
        var userId = Guid.NewGuid();
        var user = new Mock<IUser>();
        user.Setup(u => u.Id).Returns(userId);
        user.Setup(u => u.Email).Returns("pat@example.com");
        var challenge = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var options = new PasskeyOptions
        {
            RelyingPartyId = "example.com",
            RelyingPartyName = "Example",
            Origin = "https://login.example.com",
            UserVerification = "required",
            Attestation = "none",
            RequireResidentKey = true
        };
        var existingCredentialId = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var credential = CreateCredential(userId, existingCredentialId);
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);

        using var document = JsonDocument.Parse(validator.CreateRegistrationOptions(options, user.Object, "Work laptop", challenge, [credential]));
        var root = document.RootElement;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(root.GetProperty("challenge").GetString(), Is.EqualTo(challenge));
            Assert.That(root.GetProperty("rp").GetProperty("id").GetString(), Is.EqualTo("example.com"));
            Assert.That(root.GetProperty("rp").GetProperty("name").GetString(), Is.EqualTo("Example"));
            Assert.That(root.GetProperty("user").GetProperty("id").GetString(), Is.EqualTo(Base64Url.Encode(userId.ToByteArray())));
            Assert.That(root.GetProperty("user").GetProperty("name").GetString(), Is.EqualTo("pat@example.com"));
            Assert.That(root.GetProperty("user").GetProperty("displayName").GetString(), Is.EqualTo("Work laptop"));
            Assert.That(root.GetProperty("authenticatorSelection").GetProperty("residentKey").GetString(), Is.EqualTo("required"));
            Assert.That(root.GetProperty("authenticatorSelection").GetProperty("userVerification").GetString(), Is.EqualTo("required"));
            Assert.That(root.GetProperty("attestation").GetString(), Is.EqualTo("none"));
            Assert.That(root.GetProperty("excludeCredentials")[0].GetProperty("id").GetString(), Is.EqualTo(existingCredentialId));
        }
    }

    [Test]
    public void CreateAuthenticationOptionsShouldUseAshlarChallengeAndAllowedCredentials()
    {
        var userId = Guid.NewGuid();
        var challenge = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var options = new PasskeyOptions
        {
            RelyingPartyId = "example.com",
            RelyingPartyName = "Example",
            Origin = "https://login.example.com",
            UserVerification = "preferred"
        };
        var credentialId = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var credential = CreateCredential(userId, credentialId);
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);

        using var document = JsonDocument.Parse(validator.CreateAuthenticationOptions(options, challenge, [credential]));
        var root = document.RootElement;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(root.GetProperty("challenge").GetString(), Is.EqualTo(challenge));
            Assert.That(root.GetProperty("rpId").GetString(), Is.EqualTo("example.com"));
            Assert.That(root.GetProperty("userVerification").GetString(), Is.EqualTo("preferred"));
            Assert.That(root.GetProperty("allowCredentials")[0].GetProperty("id").GetString(), Is.EqualTo(credentialId));
            Assert.That(root.GetProperty("allowCredentials")[0].GetProperty("transports").EnumerateArray().Select(t => t.GetString()), Is.EquivalentTo(ExpectedTransports));
        }
    }

    [Test]
    public void CreateAuthenticationOptionsShouldHandleMissingAndInvalidCredentialMetadata()
    {
        var userId = Guid.NewGuid();
        var challenge = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var options = new PasskeyOptions
        {
            RelyingPartyId = "example.com",
            RelyingPartyName = "Example",
            Origin = "https://login.example.com"
        };
        var withoutMetadata = CreateCredential(userId, Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));
        withoutMetadata.Metadata = null;
        var withInvalidTransport = CreateCredential(userId, Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));
        withInvalidTransport.Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata
        {
            PublicKey = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)),
            Transports = ["not-a-transport"]
        }, PasskeyJson.Options);
        var withNullMetadata = CreateCredential(userId, Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));
        withNullMetadata.Metadata = "null";
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);

        using var document = JsonDocument.Parse(validator.CreateAuthenticationOptions(options, challenge, [withoutMetadata, withInvalidTransport, withNullMetadata]));
        var allowCredentials = document.RootElement.GetProperty("allowCredentials").EnumerateArray().ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(allowCredentials, Has.Length.EqualTo(3));
            Assert.That(allowCredentials[0].TryGetProperty("transports", out var firstTransports) ? firstTransports.GetArrayLength() : 0, Is.Zero);
            Assert.That(allowCredentials[1].TryGetProperty("transports", out var secondTransports) ? secondTransports.GetArrayLength() : 0, Is.Zero);
            Assert.That(allowCredentials[2].TryGetProperty("transports", out var thirdTransports) ? thirdTransports.GetArrayLength() : 0, Is.Zero);
        }
    }

    [Test]
    public void CreateRegistrationOptionsShouldMapAlternativeOptionValues()
    {
        var user = new Mock<IUser>();
        user.Setup(u => u.Id).Returns(Guid.NewGuid());
        user.Setup(u => u.Email).Returns("pat@example.com");
        var challenge = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        var options = new PasskeyOptions
        {
            RelyingPartyId = "example.com",
            RelyingPartyName = "Example",
            Origin = "https://login.example.com",
            UserVerification = "discouraged",
            Attestation = "direct",
            RequireResidentKey = false
        };
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);

        using var document = JsonDocument.Parse(validator.CreateRegistrationOptions(options, user.Object, "", challenge, []));
        var root = document.RootElement;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(root.GetProperty("user").GetProperty("displayName").GetString(), Is.EqualTo("pat@example.com"));
            Assert.That(root.GetProperty("authenticatorSelection").GetProperty("residentKey").GetString(), Is.EqualTo("preferred"));
            Assert.That(root.GetProperty("authenticatorSelection").GetProperty("userVerification").GetString(), Is.EqualTo("discouraged"));
            Assert.That(root.GetProperty("attestation").GetString(), Is.EqualTo("direct"));
        }
    }

    [TestCase("enterprise", "enterprise")]
    [TestCase("indirect", "indirect")]
    [TestCase("unexpected", "none")]
    public void CreateRegistrationOptionsShouldMapRemainingAttestationValues(string configuredAttestation, string expectedAttestation)
    {
        var user = new Mock<IUser>();
        user.Setup(u => u.Id).Returns(Guid.NewGuid());
        user.Setup(u => u.Email).Returns("pat@example.com");
        var options = new PasskeyOptions
        {
            RelyingPartyId = "example.com",
            RelyingPartyName = "Example",
            Origin = "https://login.example.com",
            Attestation = configuredAttestation
        };
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);

        using var document = JsonDocument.Parse(validator.CreateRegistrationOptions(options, user.Object, "Laptop", Base64Url.Encode(RandomNumberGenerator.GetBytes(32)), []));

        Assert.That(document.RootElement.GetProperty("attestation").GetString(), Is.EqualTo(expectedAttestation));
    }

    [Test]
    public void VerifyRegistrationAsyncShouldRejectNullResponse()
    {
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);
        var challenge = CreateChallenge("passkey-registration");

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => validator.VerifyRegistrationAsync(CreateOptions(), challenge, JsonDocument.Parse("null").RootElement));

        Assert.That(ex?.Message, Is.EqualTo("Passkey registration response was empty."));
    }

    [Test]
    public void VerifyRegistrationAsyncShouldInvokeFidoValidationForNonNullResponses()
    {
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);
        var challenge = CreateChallenge("passkey-registration");

        Assert.That(async () => await validator.VerifyRegistrationAsync(CreateOptions(), challenge, JsonDocument.Parse("{}").RootElement), Throws.Exception);
    }

    [Test]
    public async Task VerifyRegistrationAsyncShouldReturnVerifiedCredential()
    {
        var credentialId = RandomNumberGenerator.GetBytes(32);
        var publicKey = RandomNumberGenerator.GetBytes(65);
        var aaGuid = Guid.NewGuid();
        var repository = new Mock<IIdentityRepository>();
        var validator = new Fido2PasskeyCeremonyValidator(
            repository.Object,
            async (_, parameters, ct) =>
            {
                Assert.That(await parameters.IsCredentialIdUniqueToUserCallback(new IsCredentialIdUniqueToUserParams(credentialId, new Fido2User()), ct), Is.True);
                return new RegisteredPublicKeyCredential
                {
                    Id = credentialId,
                    PublicKey = publicKey,
                    SignCount = 7,
                    Transports = [AuthenticatorTransport.Usb, AuthenticatorTransport.Internal],
                    AaGuid = aaGuid
                };
            },
            (_, _, _) => throw new InvalidOperationException("Authentication should not be invoked."));
        var challenge = CreateChallenge("passkey-registration");
        var options = CreateOptions();
        options.RequireResidentKey = true;

        var result = await validator.VerifyRegistrationAsync(options, challenge, JsonDocument.Parse("{}").RootElement);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.CredentialId, Is.EqualTo(Base64Url.Encode(credentialId)));
            Assert.That(result.PublicKey, Is.EqualTo(Base64Url.Encode(publicKey)));
            Assert.That(result.SignCount, Is.EqualTo(7));
            Assert.That(result.Transports, Is.EqualTo(ExpectedVerifiedTransports));
            Assert.That(result.Aaguid, Is.EqualTo(aaGuid.ToString("D")));
            Assert.That(result.Discoverable, Is.True);
        }
    }

    [Test]
    public async Task VerifyRegistrationAsyncShouldHandleOptionalCredentialFields()
    {
        var credentialId = RandomNumberGenerator.GetBytes(32);
        var publicKey = RandomNumberGenerator.GetBytes(65);
        var validator = new Fido2PasskeyCeremonyValidator(
            new Mock<IIdentityRepository>().Object,
            (_, _, _) => Task.FromResult(new RegisteredPublicKeyCredential
            {
                Id = credentialId,
                PublicKey = publicKey,
                SignCount = 0,
                Transports = null,
                AaGuid = Guid.Empty
            }),
            (_, _, _) => throw new InvalidOperationException("Authentication should not be invoked."));
        var challenge = CreateChallenge("passkey-registration");
        var options = CreateOptions();
        options.RequireResidentKey = false;

        var result = await validator.VerifyRegistrationAsync(options, challenge, JsonDocument.Parse("{}").RootElement);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Transports, Is.Empty);
            Assert.That(result.Aaguid, Is.Null);
            Assert.That(result.Discoverable, Is.False);
        }
    }

    [Test]
    public void VerifyAuthenticationAsyncShouldRejectMissingMetadata()
    {
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);
        var challenge = CreateChallenge("passkey-authentication");
        var credential = CreateCredential(Guid.NewGuid(), Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));
        credential.Metadata = null;

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => validator.VerifyAuthenticationAsync(CreateOptions(), challenge, credential, JsonDocument.Parse("{}").RootElement));

        Assert.That(ex?.Message, Is.EqualTo("Passkey credential metadata was empty."));
    }

    [Test]
    public void VerifyAuthenticationAsyncShouldRejectInvalidMetadata()
    {
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);
        var challenge = CreateChallenge("passkey-authentication");
        var credential = CreateCredential(Guid.NewGuid(), Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));
        credential.Metadata = "null";

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => validator.VerifyAuthenticationAsync(CreateOptions(), challenge, credential, JsonDocument.Parse("{}").RootElement));

        Assert.That(ex?.Message, Is.EqualTo("Passkey credential metadata was invalid."));
    }

    [Test]
    public void VerifyAuthenticationAsyncShouldRejectNullResponse()
    {
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);
        var challenge = CreateChallenge("passkey-authentication");
        var credential = CreateCredential(Guid.NewGuid(), Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));

        var ex = Assert.ThrowsAsync<InvalidOperationException>(() => validator.VerifyAuthenticationAsync(CreateOptions(), challenge, credential, JsonDocument.Parse("null").RootElement));

        Assert.That(ex?.Message, Is.EqualTo("Passkey authentication response was empty."));
    }

    [Test]
    public void VerifyAuthenticationAsyncShouldInvokeFidoValidationForNonNullResponses()
    {
        var validator = new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object);
        var challenge = CreateChallenge("passkey-authentication");
        var credential = CreateCredential(challenge.UserId!.Value, Base64Url.Encode(RandomNumberGenerator.GetBytes(32)));

        Assert.That(async () => await validator.VerifyAuthenticationAsync(CreateOptions(), challenge, credential, JsonDocument.Parse("{}").RootElement), Throws.Exception);
    }

    [TestCase("required", true)]
    [TestCase("preferred", false)]
    public async Task VerifyAuthenticationAsyncShouldReturnVerifiedAssertion(string userVerification, bool expectedVerified)
    {
        var credentialIdBytes = RandomNumberGenerator.GetBytes(32);
        var userId = Guid.NewGuid();
        var challenge = CreateChallenge("passkey-authentication", userId);
        var credential = CreateCredential(userId, Base64Url.Encode(credentialIdBytes));
        var callbackChecks = 0;
        var validator = new Fido2PasskeyCeremonyValidator(
            new Mock<IIdentityRepository>().Object,
            (_, _, _) => throw new InvalidOperationException("Registration should not be invoked."),
            async (_, parameters, ct) =>
            {
                callbackChecks++;
                using (Assert.EnterMultipleScope())
                {
                    Assert.That(await parameters.IsUserHandleOwnerOfCredentialIdCallback(new IsUserHandleOwnerOfCredentialIdParams(credentialIdBytes, null!), ct), Is.True);
                    Assert.That(await parameters.IsUserHandleOwnerOfCredentialIdCallback(new IsUserHandleOwnerOfCredentialIdParams(credentialIdBytes, userId.ToByteArray()), ct), Is.True);
                    Assert.That(await parameters.IsUserHandleOwnerOfCredentialIdCallback(new IsUserHandleOwnerOfCredentialIdParams(RandomNumberGenerator.GetBytes(32), userId.ToByteArray()), ct), Is.False);
                }

                return new VerifyAssertionResult
                {
                    CredentialId = credentialIdBytes,
                    SignCount = 11
                };
            });
        var options = CreateOptions();
        options.UserVerification = userVerification;

        var result = await validator.VerifyAuthenticationAsync(options, challenge, credential, JsonDocument.Parse("{}").RootElement);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.CredentialId, Is.EqualTo(credential.ProviderKey));
            Assert.That(result.SignCount, Is.EqualTo(11));
            Assert.That(result.UserVerified, Is.EqualTo(expectedVerified));
            Assert.That(callbackChecks, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task VerifyAuthenticationAsyncShouldClampInvalidStoredSignCount()
    {
        var credentialIdBytes = RandomNumberGenerator.GetBytes(32);
        var userId = Guid.NewGuid();
        var challenge = CreateChallenge("passkey-authentication", userId);
        var credential = CreateCredential(userId, Base64Url.Encode(credentialIdBytes));
        credential.Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata
        {
            PublicKey = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)),
            SignCount = -1
        }, PasskeyJson.Options);
        uint? storedSignCount = null;
        var validator = new Fido2PasskeyCeremonyValidator(
            new Mock<IIdentityRepository>().Object,
            (_, _, _) => throw new InvalidOperationException("Registration should not be invoked."),
            (_, parameters, _) =>
            {
                storedSignCount = parameters.StoredSignatureCounter;
                return Task.FromResult(new VerifyAssertionResult
                {
                    CredentialId = credentialIdBytes,
                    SignCount = 1
                });
            });

        await validator.VerifyAuthenticationAsync(CreateOptions(), challenge, credential, JsonDocument.Parse("{}").RootElement);

        Assert.That(storedSignCount, Is.Zero);
    }

    private static UserCredential CreateCredential(Guid userId, string credentialId)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = AuthenticationProviderKey.Passkey.Type,
            ProviderName = AuthenticationProviderKey.Passkey.Name,
            ProviderKey = credentialId,
            Version = "version",
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active,
            Metadata = JsonSerializer.Serialize(new PasskeyCredentialMetadata
            {
                PublicKey = Base64Url.Encode(RandomNumberGenerator.GetBytes(32)),
                Transports = ExpectedTransports
            }, PasskeyJson.Options)
        };
    }

    private static PasskeyOptions CreateOptions()
    {
        return new PasskeyOptions
        {
            RelyingPartyId = "example.com",
            RelyingPartyName = "Example",
            Origin = "https://login.example.com"
        };
    }

    private static PasskeyChallenge CreateChallenge(string purpose, Guid? userId = null)
    {
        var challengeValue = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
        return new PasskeyChallenge
        {
            Id = Guid.NewGuid(),
            Version = "v1",
            Purpose = purpose,
            UserId = userId ?? Guid.NewGuid(),
            Challenge = challengeValue,
            OptionsJson = purpose == "passkey-registration"
                ? new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object).CreateRegistrationOptions(CreateOptions(), new TestUser(Guid.NewGuid(), "pat@example.com"), "Laptop", challengeValue, [])
                : new Fido2PasskeyCeremonyValidator(new Mock<IIdentityRepository>().Object).CreateAuthenticationOptions(CreateOptions(), challengeValue, []),
            RelyingPartyId = "example.com",
            Origin = "https://login.example.com",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
        };
    }
}


