using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;
using Moq;

namespace Ashlar.Tests.Identity.Features.Mfa;

internal sealed class MfaPolicyEvaluatorTests
{
    private static readonly string[] TotpFactor = ["totp"];
    private static readonly string[] CompositeFactors = ["TOTP", "email_code"];
    private readonly AuthenticationContext _context = new(IpAddress: "127.0.0.1");

    [Test]
    public async Task MfaPolicyEvaluatorAlwaysReturnsNoMfaRequired()
    {
        var user = CreateUser();
        var result = await new MfaPolicyEvaluator().EvaluateAsync(user.Object, _context);

        Assert.That(result.IsMfaRequired, Is.False);
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void MfaPolicyEvaluatorThrowsWhenArgumentsAreNull()
    {
        var evaluator = new MfaPolicyEvaluator();
        var user = CreateUser();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(null!, _context));
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(user.Object, null!));
        }
    }

    [Test]
    public async Task RequireMfaForAllUsersPolicyEvaluatorRequiresConfiguredFactorsForActiveUsers()
    {
        var evaluator = new RequireMfaForAllUsersPolicyEvaluator(Options.Create(new RequireMfaForAllUsersPolicyOptions
        {
            RequiredFactors = { "totp" }
        }));

        var result = await evaluator.EvaluateAsync(CreateUser().Object, _context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsMfaRequired, Is.True);
            Assert.That(result.Requirement, Is.Not.Null);
            Assert.That(result.Requirement?.RequiredFactors, Is.EquivalentTo(TotpFactor));
        }
    }

    [Test]
    public async Task RequireMfaForAllUsersPolicyEvaluatorIgnoresInactiveUsers()
    {
        var evaluator = new RequireMfaForAllUsersPolicyEvaluator(Options.Create(new RequireMfaForAllUsersPolicyOptions
        {
            RequiredFactors = { "totp" }
        }));

        var result = await evaluator.EvaluateAsync(CreateUser(isActive: false).Object, _context);

        Assert.That(result.IsMfaRequired, Is.False);
    }

    [Test]
    public void RequireMfaForAllUsersPolicyEvaluatorValidatesOptionsAndArguments()
    {
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.Throws<ArgumentNullException>(() => _ = new RequireMfaForAllUsersPolicyEvaluator(null!));
            Assert.Throws<OptionsValidationException>(() => _ = new RequireMfaForAllUsersPolicyEvaluator(Options.Create(new RequireMfaForAllUsersPolicyOptions())));
            Assert.That(RequireMfaForAllUsersPolicyOptions.Validate(null), Is.False);
            Assert.That(RequireMfaForAllUsersPolicyOptions.Validate(new RequireMfaForAllUsersPolicyOptions { RequiredFactors = { " " } }), Is.False);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void RequireMfaForAllUsersPolicyEvaluatorThrowsWhenEvaluateArgumentsAreNull()
    {
        var evaluator = new RequireMfaForAllUsersPolicyEvaluator(Options.Create(new RequireMfaForAllUsersPolicyOptions
        {
            RequiredFactors = { "totp" }
        }));
        var user = CreateUser();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(null!, _context));
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(user.Object, null!));
        }
    }

    [Test]
    public async Task RequireMfaWhenCredentialExistsPolicyEvaluatorRequiresMfaForActiveCredential()
    {
        var user = CreateUser();
        var repository = CreateRepositoryReturning(Credential(user.Object.Id, ProviderType.Mfa, "totp"));
        var evaluator = CreateCredentialEvaluator(repository.Object);

        var result = await evaluator.EvaluateAsync(user.Object, _context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsMfaRequired, Is.True);
            Assert.That(result.Requirement, Is.Not.Null);
            Assert.That(result.Requirement?.RequiredFactors, Is.EquivalentTo(TotpFactor));
        }
    }

    [Test]
    public async Task RequireMfaWhenCredentialExistsPolicyEvaluatorIgnoresRevokedExpiredAndMissingCredentials()
    {
        var user = CreateUser();
        var now = new DateTimeOffset(2026, 5, 8, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new StaticTimeProvider(now);

        var cases = new[]
        {
            Credential(user.Object.Id, ProviderType.Mfa, "totp", status: CredentialStatus.Revoked),
            Credential(user.Object.Id, ProviderType.Mfa, "totp", revokedAt: now.AddMinutes(-1)),
            Credential(user.Object.Id, ProviderType.Mfa, "totp", expiresAt: now),
            Credential(user.Object.Id, ProviderType.Mfa, "totp", expiresAt: now.AddMinutes(-1)),
            null
        };

        foreach (var credential in cases)
        {
            var repository = CreateRepositoryReturning(credential);
            var result = await CreateCredentialEvaluator(repository.Object, timeProvider).EvaluateAsync(user.Object, _context);
            Assert.That(result.IsMfaRequired, Is.False);
        }
    }

    [Test]
    public async Task RequireMfaWhenCredentialExistsPolicyEvaluatorIgnoresWrongProvider()
    {
        var user = CreateUser();
        var repository = new Mock<ICredentialRepository>(MockBehavior.Strict);
        repository.Setup(r => r.GetCredentialForUserAsync(user.Object.Id, ProviderType.Mfa, "totp", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);

        var result = await CreateCredentialEvaluator(repository.Object).EvaluateAsync(user.Object, _context);

        Assert.That(result.IsMfaRequired, Is.False);
        repository.Verify(r => r.GetCredentialForUserAsync(
            It.IsAny<Guid>(),
            ProviderType.EmailCode,
            It.IsAny<string>(),
            It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task RequireMfaWhenCredentialExistsPolicyEvaluatorChecksMultipleMatchingProviders()
    {
        var user = CreateUser();
        var repository = new Mock<ICredentialRepository>(MockBehavior.Strict);
        repository.Setup(r => r.GetCredentialForUserAsync(user.Object.Id, ProviderType.Mfa, "totp", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync((UserCredential?)null);
        repository.Setup(r => r.GetCredentialForUserAsync(user.Object.Id, ProviderType.Mfa, "webauthn", null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Credential(user.Object.Id, ProviderType.Mfa, "webauthn"));
        var evaluator = new RequireMfaWhenCredentialExistsPolicyEvaluator(
            repository.Object,
            Options.Create(new CredentialBackedMfaPolicyOptions
            {
                CredentialProviderKeys =
                {
                    new AuthenticationProviderKey(ProviderType.Mfa, "totp"),
                    new AuthenticationProviderKey(ProviderType.Mfa, "webauthn")
                },
                RequiredFactors = { "totp" }
            }),
            TimeProvider.System);

        var result = await evaluator.EvaluateAsync(user.Object, _context);

        Assert.That(result.IsMfaRequired, Is.True);
    }

    [Test]
    public async Task RequireMfaWhenCredentialExistsPolicyEvaluatorIgnoresInactiveUserWithoutRepositoryQuery()
    {
        var repository = new Mock<ICredentialRepository>(MockBehavior.Strict);
        var result = await CreateCredentialEvaluator(repository.Object).EvaluateAsync(CreateUser(isActive: false).Object, _context);

        Assert.That(result.IsMfaRequired, Is.False);
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void RequireMfaWhenCredentialExistsPolicyEvaluatorValidatesOptionsAndArguments()
    {
        var repository = Mock.Of<ICredentialRepository>();
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new RequireMfaWhenCredentialExistsPolicyEvaluator(null!, Options.Create(new CredentialBackedMfaPolicyOptions())));
            Assert.Throws<ArgumentNullException>(() => _ = new RequireMfaWhenCredentialExistsPolicyEvaluator(repository, null!));
            Assert.Throws<OptionsValidationException>(() => _ = new RequireMfaWhenCredentialExistsPolicyEvaluator(repository, Options.Create(new CredentialBackedMfaPolicyOptions())));
            Assert.That(CredentialBackedMfaPolicyOptions.Validate(null), Is.False);
            Assert.That(CredentialBackedMfaPolicyOptions.Validate(new CredentialBackedMfaPolicyOptions { CredentialProviderKeys = { default }, RequiredFactors = { "totp" } }), Is.False);
            Assert.That(CredentialBackedMfaPolicyOptions.Validate(new CredentialBackedMfaPolicyOptions { CredentialProviderKeys = { new AuthenticationProviderKey(ProviderType.Mfa, "totp") }, RequiredFactors = { " " } }), Is.False);
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void RequireMfaWhenCredentialExistsPolicyEvaluatorThrowsWhenEvaluateArgumentsAreNull()
    {
        var evaluator = CreateCredentialEvaluator(Mock.Of<ICredentialRepository>());
        var user = CreateUser();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(null!, _context));
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(user.Object, null!));
        }
    }

    [Test]
    public async Task CompositeMfaPolicyEvaluatorUnionsRequiredFactorsCaseInsensitively()
    {
        var evaluator = new CompositeMfaPolicyEvaluator([
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(true, new MfaRequirement(["TOTP", " email_code "])))),
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"])))),
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(true))),
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(false)))
        ]);

        var result = await evaluator.EvaluateAsync(CreateUser().Object, _context);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsMfaRequired, Is.True);
            Assert.That(result.Requirement, Is.Not.Null);
            Assert.That(result.Requirement?.RequiredFactors, Is.EquivalentTo(CompositeFactors));
        }
    }

    [Test]
    public async Task CompositeMfaPolicyEvaluatorReturnsNoMfaWhenNoEvaluatorRequiresMfa()
    {
        var evaluator = new CompositeMfaPolicyEvaluator([
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(false)))
        ]);

        var result = await evaluator.EvaluateAsync(CreateUser().Object, _context);

        Assert.That(result.IsMfaRequired, Is.False);
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void CompositeMfaPolicyEvaluatorValidatesArguments()
    {
        var evaluator = new CompositeMfaPolicyEvaluator([]);
        var user = CreateUser();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new CompositeMfaPolicyEvaluator(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(null!, _context));
            Assert.ThrowsAsync<ArgumentNullException>(() => evaluator.EvaluateAsync(user.Object, null!));
            Assert.Throws<ArgumentNullException>(() => _ = new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(null!));
        }
    }

    [Test]
    public async Task CompositeMfaPolicyEvaluatorComposesWithAuthenticationOrchestrator()
    {
        var user = CreateUser();
        var assertion = new Mock<IAuthenticationAssertion>();
        var pipeline = new Mock<IAuthenticationPipeline>();
        var factorPipeline = new Mock<IAuthenticationFactorPipeline>();
        var handshakeService = new Mock<IAuthenticationHandshakeService>();
        var policy = new CompositeMfaPolicyEvaluator([
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(false))),
            new MfaPolicyEvaluatorComponent<StaticMfaPolicyEvaluator>(new StaticMfaPolicyEvaluator(new MfaPolicyEvaluation(true, new MfaRequirement(["totp"]))))
        ]);
        var orchestrator = new AuthenticationOrchestrator(pipeline.Object, factorPipeline.Object, handshakeService.Object, policy, Mock.Of<IAuthenticationProviderRegistry>());
        pipeline.Setup(p => p.LoginAsync(_context, assertion.Object, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationResponse(true, user.Object, AuthenticationStatus.Success));
        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            user.Object.Id,
            "hash",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(5),
            false,
            false,
            new HashSet<string> { "totp" },
            new HashSet<string>());
        handshakeService.Setup(h => h.CreateHandshakeAsync(It.IsAny<CreateAuthenticationHandshakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result.Success(new AuthenticationHandshakeCreated(handshake, "token")));

        var result = await orchestrator.AuthenticateAsync(_context, assertion.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(MfaAuthenticationStatus.MfaRequired));
            Assert.That(result.RequiredFactors, Is.EquivalentTo(TotpFactor));
        }
    }

    private static RequireMfaWhenCredentialExistsPolicyEvaluator CreateCredentialEvaluator(ICredentialRepository repository, TimeProvider? timeProvider = null)
    {
        return new RequireMfaWhenCredentialExistsPolicyEvaluator(
            repository,
            Options.Create(new CredentialBackedMfaPolicyOptions
            {
                CredentialProviderKeys = { new AuthenticationProviderKey(ProviderType.Mfa, "totp") },
                RequiredFactors = { "totp" }
            }),
            timeProvider);
    }

    private static Mock<ICredentialRepository> CreateRepositoryReturning(UserCredential? credential)
    {
        var repository = new Mock<ICredentialRepository>(MockBehavior.Strict);
        repository.Setup(r => r.GetCredentialForUserAsync(It.IsAny<Guid>(), It.IsAny<ProviderType>(), It.IsAny<string>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(credential);
        return repository;
    }

    private static Mock<IUser> CreateUser(bool isActive = true)
    {
        var user = new Mock<IUser>();
        user.Setup(u => u.Id).Returns(Guid.NewGuid());
        user.Setup(u => u.IsActive).Returns(isActive);
        return user;
    }

    private static UserCredential Credential(
        Guid userId,
        ProviderType type,
        string providerName,
        CredentialStatus status = CredentialStatus.Active,
        DateTimeOffset? revokedAt = null,
        DateTimeOffset? expiresAt = null)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = type,
            ProviderName = providerName,
            ProviderKey = userId.ToString("D"),
            Version = "1",
            CreatedAt = new DateTimeOffset(2026, 5, 8, 11, 0, 0, TimeSpan.Zero),
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt,
            Status = status
        };
    }

    private sealed class StaticMfaPolicyEvaluator(MfaPolicyEvaluation evaluation) : IMfaPolicyEvaluator
    {
        public Task<MfaPolicyEvaluation> EvaluateAsync(IUser user, AuthenticationContext context, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(evaluation);
        }
    }

    private sealed class StaticTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
