using Ashlar.Authorization.Abstractions;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Operational.Configuration;
using Ashlar.Security.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Ashlar.Tests.Operational.Configuration;

internal sealed class AshlarConfigurationValidatorTests
{
    private static readonly string[] ExpectedAggregatedIssueCodes = ["ONE", "TWO"];
    private const string CallbackUriIssueCodePrefix = "ASHLAR-CONFIG-CALLBACK-URI-";

    [Test]
    public async Task ValidatorAggregatesMultipleChecks()
    {
        var services = new ServiceCollection();
        services.AddScoped<IAshlarConfigurationValidator, AshlarConfigurationValidator>();
        services.AddSingleton<IAshlarConfigurationCheck>(new StubConfigurationCheck(
            new AshlarConfigurationIssue("ONE", AshlarConfigurationIssueSeverity.Information, "One", "Review one.", "Test")));
        services.AddSingleton<IAshlarConfigurationCheck>(new StubConfigurationCheck(
            new AshlarConfigurationIssue("TWO", AshlarConfigurationIssueSeverity.Warning, "Two", "Review two.", "Test")));

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Issues.Select(issue => issue.Code), Is.EquivalentTo(ExpectedAggregatedIssueCodes));
            Assert.That(result.HasWarnings, Is.True);
            Assert.That(result.HasErrors, Is.False);
            Assert.That(result.IsValid, Is.True);
        }
    }

    [Test]
    public async Task ValidatorReturnsValidResultWhenNoIssuesExist()
    {
        var services = new ServiceCollection();
        services.AddScoped<IAshlarConfigurationValidator, AshlarConfigurationValidator>();
        services.AddSingleton<IAshlarConfigurationCheck, EmptyConfigurationCheck>();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Issues, Is.Empty);
            Assert.That(result.HasWarnings, Is.False);
            Assert.That(result.HasErrors, Is.False);
            Assert.That(result.IsValid, Is.True);
        }
    }

    [Test]
    public void ValidationResultRejectsNullIssues()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => _ = new AshlarConfigurationValidationResult(null!));

        Assert.That(exception.ParamName, Is.EqualTo("issues"));
    }

    [Test]
    public void ValidatorRejectsNullServiceProvider()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => _ = new AshlarConfigurationValidator(null!, []));

        Assert.That(exception.ParamName, Is.EqualTo("serviceProvider"));
    }

    [Test]
    public void ValidatorRejectsNullChecks()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<ArgumentNullException>(() => _ = new AshlarConfigurationValidator(provider, null!));

        Assert.That(exception.ParamName, Is.EqualTo("checks"));
    }

    [Test]
    public async Task CoreCheckReportsExpectedDefaultIdentityIssues()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.UserRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.CredentialRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.SecretProtectorMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.UserAdministrationRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.CredentialAdministrationRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.SecurityEventAdministrationRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthenticationSessionAdministrationRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.NullSecurityEventSink, AshlarConfigurationIssueSeverity.Warning);
            AssertIssue(result, AshlarConfigurationIssueCodes.InMemoryAuthenticationRateLimiter, AshlarConfigurationIssueSeverity.Warning);
            AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Information);
            Assert.That(result.HasErrors, Is.True);
            Assert.That(result.IsValid, Is.False);
        }
    }

    [Test]
    public async Task CoreCheckReportsDetailedInMemoryRateLimiterWarning()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        var issue = AssertIssue(result, AshlarConfigurationIssueCodes.InMemoryAuthenticationRateLimiter, AshlarConfigurationIssueSeverity.Warning);
        var text = $"{issue.Message} {issue.Recommendation}";

        using (Assert.EnterMultipleScope())
        {
            Assert.That(text, Does.Contain("process-local"));
            Assert.That(text, Does.Contain("resets on process restart"));
            Assert.That(text, Does.Contain("does not coordinate across multiple app instances"));
            Assert.That(text, Does.Contain("PostgreSQL"));
            Assert.That(text, Does.Contain("SQLite"));
            Assert.That(text, Does.Contain("Redis"));
            Assert.That(text, Does.Contain("Redis or PostgreSQL for multi-instance deployments"));
            Assert.That(text, Does.Contain("SQLite is persistent but still single-instance oriented"));
        }
    }

    [Test]
    public async Task CoreCheckReportsWarningForNullTransactionProviderWithRepositories()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckReportsWarningForMissingTransactionProviderWithRepositories()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckReportsWarningForNullTransactionProviderWithOnlyCredentialRepository()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckReportsWarningForNullTransactionProviderWithAuthorizationRepository()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IAuthorizationGrantRepository>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckDoesNotTreatPasskeyChallengeRepositoryAsCoreDurableTransactionSignal()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IPasskeyChallengeRepository>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Information);
    }

    [Test]
    public async Task CoreCheckReportsFeatureRepositoryIssuesWhenFeaturesAreRegistered()
    {
        var services = new ServiceCollection();
        services.AddAshlarInvitations();
        services.AddAshlarBootstrap();
        services.AddAshlarMfaHandshakes();
        services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.InvitationRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.BootstrapStateRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthenticationHandshakeRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthorizationGrantRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
        }
    }

    [Test]
    public async Task CoreCheckReportsBootstrapSetupAuthorizationErrorWhenBootstrapHasNoSecureGate()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.BootstrapSetupAuthorizationMissing, AshlarConfigurationIssueSeverity.Error);
    }

    [Test]
    public async Task CoreCheckDoesNotReportBootstrapSetupAuthorizationIssueWhenSecretIsConfigured()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options => options.SetupSecret = "configured-secret");

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.BootstrapSetupAuthorizationMissing));
    }

    [Test]
    public async Task CoreCheckDoesNotRequireAuthorizationForBootstrapWithoutGrants()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options => options.SetupSecret = "configured-secret");

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.BootstrapGrantServiceMissing));
    }

    [Test]
    public async Task CoreCheckReportsBootstrapGrantServiceMissingWhenGrantsAreConfiguredWithoutAuthorization()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options =>
        {
            options.SetupSecret = "configured-secret";
            options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        });

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.BootstrapGrantServiceMissing, AshlarConfigurationIssueSeverity.Error);
    }

    [Test]
    public async Task CoreCheckDoesNotReportBootstrapGrantServiceMissingWhenAuthorizationIsRegistered()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options =>
        {
            options.SetupSecret = "configured-secret";
            options.Grants.Add(new BootstrapGrantTemplate { Role = "admin" });
        });
        services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.BootstrapGrantServiceMissing));
    }

    [Test]
    public async Task CoreCheckReportsBootstrapOptionsIssueInsteadOfThrowingWhenOptionsAreInvalid()
    {
        var services = new ServiceCollection();
        services.AddAshlarBootstrap(options =>
        {
            options.SetupSecret = "configured-secret";
            options.Grants.Add(new BootstrapGrantTemplate());
        });

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.BootstrapOptionsInvalid, AshlarConfigurationIssueSeverity.Error);
    }

    [Test]
    public async Task CoreCheckDoesNotRequireCredentialRepositoryForInvitationServiceAlone()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IInvitationService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.UserRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.InvitationRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.CredentialRepositoryMissing));
        }
    }

    [Test]
    public async Task CoreCheckDoesNotRequireCredentialRepositoryForBootstrapServiceAlone()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IBootstrapService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.UserRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.BootstrapStateRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.InvitationRepositoryMissing));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.CredentialRepositoryMissing));
        }
    }

    [Test]
    public async Task CoreCheckReportsSharedRepositoryIssuesWhenAccountSecurityServiceIsRegisteredWithoutIdentityService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IAccountSecurityService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.UserRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.CredentialRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
        }
    }

    [Test]
    public async Task CoreCheckReportsSharedRepositoryIssuesWhenEmailChangeServiceIsRegisteredWithoutIdentityService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IEmailChangeService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.UserRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.CredentialRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.SecretProtectorMissing, AshlarConfigurationIssueSeverity.Error);
        }
    }

    [Test]
    public async Task CoreCheckReportsEmailSenderIssueWhenEmailFlowIsRegisteredWithoutSender()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IEmailVerificationService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.EmailSenderNotConfigured, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckReportsEmailSenderIssueWhenEmailFlowUsesNullSender()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IEmailVerificationService>());
        services.AddSingleton<IEmailSender, NullEmailSender>();
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.EmailSenderNotConfigured, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckDoesNotReportEmailSenderIssueWhenEmailFlowUsesCustomSender()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IEmailVerificationService>());
        services.AddSingleton<IEmailSender, CustomEmailSender>();
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.EmailSenderNotConfigured));
    }

    [Test]
    public async Task CoreCheckDoesNotReportEmailSenderIssueWhenNoEmailFlowIsRegistered()
    {
        var services = new ServiceCollection();
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.EmailSenderNotConfigured));
    }

    [Test]
    public async Task CoreCheckDoesNotReportCallbackUriIssuesWhenNoCallbackFlowIsRegistered()
    {
        var services = new ServiceCollection();
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add("not a callback URI");
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Has.None.StartsWith(CallbackUriIssueCodePrefix));
    }

    [TestCase("magic-link")]
    [TestCase("email-verification")]
    [TestCase("email-change")]
    [TestCase("invitation")]
    [TestCase("password-reset")]
    public async Task CoreCheckReportsMissingCallbackUriAllowListWhenCallbackFlowIsRegistered(string flow)
    {
        var services = new ServiceCollection();
        RegisterCallbackFlow(services, flow);
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListMissing, AshlarConfigurationIssueSeverity.Error);
    }

    [Test]
    public async Task CoreCheckDoesNotRequireCallbackUriAllowListForEmailCodeSignIn()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IEmailCodeSignInService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Has.None.StartsWith(CallbackUriIssueCodePrefix));
    }

    [Test]
    public async Task CoreCheckDoesNotReportCallbackUriIssuesForValidHttpsAllowList()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add("https://app.example.com/account/callback");
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Has.None.StartsWith(CallbackUriIssueCodePrefix));
    }

    [Test]
    public async Task CoreCheckReportsInvalidCallbackUriAllowListEntriesWithoutExposingSecrets()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add(" ");
            options.AllowedCallbackUris.Add("not a callback URI");
            options.AllowedCallbackUris.Add("/relative?token=secret-token");
            options.AllowedCallbackUris.Add("https://user:password@app.example.com/callback?token=secret-token#fragment");
            options.AllowedCallbackUris.Add("secret-token://app.example.com/callback");
            options.AllowedCallbackUris.Add("https://app.example.com/reset/secret-token");
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();
        var callbackMessages = result.Issues
            .Where(issue => issue.Code.StartsWith(CallbackUriIssueCodePrefix, StringComparison.Ordinal))
            .Select(issue => issue.Message);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Issues.Count(issue => issue.Code == AshlarConfigurationIssueCodes.CallbackUriAllowListInvalidEntry), Is.EqualTo(5));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.CallbackUriAllowListMissing));
            Assert.That(callbackMessages, Has.Some.Contains("malformed entry"));
            Assert.That(callbackMessages, Has.None.Contains("secret-token"));
            Assert.That(callbackMessages, Has.None.Contains("password"));
            Assert.That(callbackMessages, Has.None.Contains("?"));
            Assert.That(callbackMessages, Has.None.Contains("#"));
        }
    }

    [Test]
    public async Task CoreCheckReportsMissingCallbackUriAllowListWhenAllowListIsNull()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options => options.AllowedCallbackUris = null!);
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListMissing, AshlarConfigurationIssueSeverity.Error);
    }

    [Test]
    public async Task CoreCheckReportsInsecureSchemeWarningForHttpCallbackUriAllowList()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add("http://app.example.com/");
            options.AllowedCallbackUris.Add("http://app.example.com/reset/secret-token");
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        var issues = AssertIssues(result, AshlarConfigurationIssueCodes.CallbackUriAllowListInsecureScheme, AshlarConfigurationIssueSeverity.Warning);
        Assert.That(issues.Select(issue => issue.Message), Has.None.Contains("secret-token"));
    }

    [TestCase("https://localhost/callback")]
    [TestCase("https://127.0.0.1/callback")]
    [TestCase("https://10.0.0.1/callback")]
    [TestCase("https://172.16.0.1/callback")]
    [TestCase("https://172.31.0.1/callback")]
    [TestCase("https://192.168.0.1/callback")]
    [TestCase("https://169.254.0.1/callback")]
    [TestCase("https://224.0.0.1/callback")]
    [TestCase("https://0.0.0.0/callback")]
    [TestCase("https://[::ffff:192.168.0.1]/callback")]
    [TestCase("https://[::1]/callback")]
    [TestCase("https://[::]/callback")]
    [TestCase("https://[fe80::1]/callback")]
    [TestCase("https://[fec0::1]/callback")]
    [TestCase("https://[fc00::1]/callback")]
    [TestCase("https://[ff02::1]/callback")]
    public async Task CoreCheckReportsLocalAddressWarningForLocalPrivateLinkLocalMulticastOrUnspecifiedCallbackUriAllowList(string callbackUri)
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add(callbackUri);
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListLocalAddress, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckDoesNotExposeCallbackUriPathInLocalAddressWarning()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add("https://localhost/reset/secret-token");
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        var issue = AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListLocalAddress, AshlarConfigurationIssueSeverity.Warning);
        Assert.That(issue.Message, Does.Not.Contain("secret-token"));
    }

    [TestCase("https://app.example.com/callback")]
    [TestCase("https://8.8.8.8/callback")]
    [TestCase("https://11.0.0.1/callback")]
    [TestCase("https://172.15.0.1/callback")]
    [TestCase("https://172.32.0.1/callback")]
    [TestCase("https://192.167.0.1/callback")]
    [TestCase("https://169.253.0.1/callback")]
    [TestCase("https://223.255.255.255/callback")]
    [TestCase("https://240.0.0.1/callback")]
    [TestCase("https://[::ffff:8.8.8.8]/callback")]
    [TestCase("https://[2001:4860:4860::8888]/callback")]
    public async Task CoreCheckDoesNotReportLocalAddressWarningForNonLocalCallbackUriAllowList(string callbackUri)
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add(callbackUri);
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.CallbackUriAllowListLocalAddress));
    }

    [Test]
    public async Task CoreCheckReportsMultipleCallbackUriDiagnostics()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.Configure<UriValidationOptions>(options =>
        {
            options.AllowedCallbackUris.Add("/relative");
            options.AllowedCallbackUris.Add("http://localhost/callback");
        });
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListInvalidEntry, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListInsecureScheme, AshlarConfigurationIssueSeverity.Warning);
            AssertIssue(result, AshlarConfigurationIssueCodes.CallbackUriAllowListLocalAddress, AshlarConfigurationIssueSeverity.Warning);
        }
    }

    [Test]
    public async Task CoreCheckReportsSharedRepositoryIssuesWhenEmailSignInServicesAreRegisteredWithoutIdentityService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IEmailCodeSignInService>());
        services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.UserRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            AssertIssue(result, AshlarConfigurationIssueCodes.CredentialRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.SecretProtectorMissing));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing));
        }
    }

    [Test]
    public async Task CoreCheckReportsCredentialRepositoryIssueWhenCredentialBackedMfaPolicyIsRegisteredWithoutIdentityService()
    {
        var services = new ServiceCollection();
        services.AddScoped<RequireMfaWhenCredentialExistsPolicyEvaluator>();
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.CredentialRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.UserRepositoryMissing));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.SecretProtectorMissing));
        }
    }

    [Test]
    public async Task AddAshlarAuthorizationRegistersConfigurationValidator()
    {
        var services = new ServiceCollection();

        services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            AssertIssue(result, AshlarConfigurationIssueCodes.AuthorizationGrantRepositoryMissing, AshlarConfigurationIssueSeverity.Error);
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.UserRepositoryMissing));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.CredentialRepositoryMissing));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.SecretProtectorMissing));
        }
    }

    [Test]
    public async Task CoreCheckReportsInMemorySecurityNotificationSuppressionStoreWarning()
    {
        var services = new ServiceCollection();

        services.AddAshlarSecurityNotifications();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.InMemorySecurityNotificationSuppressionStore, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task CoreCheckDoesNotReportSecurityNotificationSuppressionStoreWhenCustomStoreIsRegistered()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISecurityNotificationSuppressionStore, CustomSecurityNotificationSuppressionStore>();

        services.AddAshlarSecurityNotifications();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.InMemorySecurityNotificationSuppressionStore));
    }

    [Test]
    public async Task CoreCheckDoesNotReportDefaultIssuesWhenProductionServicesAreRegistered()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<ISecretProtector>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton<IEmailSender, CustomEmailSender>();
        services.AddSingleton<IPersistentSecurityEventSink, CustomPersistentSecurityEventSink>();
        services.AddSingleton<IAuthenticationRateLimiter, CustomAuthenticationRateLimiter>();
        services.AddSingleton<IAshlarTransactionProvider, CustomTransactionProvider>();
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        Assert.That(result.Issues, Is.Empty);
    }

    [Test]
    public async Task CoreCheckReportsAuditWarningWhenOnlySecurityEventHandlersAreRegistered()
    {
        var services = new ServiceCollection();
        services.AddAshlarSecurityEventHandler<CustomSecurityEventHandler>();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        AssertIssue(result, AshlarConfigurationIssueCodes.NullSecurityEventSink, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public async Task ChecksDoNotThrowIfOptionalServicesAreMissing()
    {
        var services = new ServiceCollection();
        services.AddAshlarConfigurationValidation();

        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.UserRepositoryMissing));
            Assert.That(result.Issues.Select(issue => issue.Code), Does.Not.Contain(AshlarConfigurationIssueCodes.EmailSenderNotConfigured));
            AssertIssue(result, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Information);
        }
    }

    [Test]
    public void AddAshlarConfigurationValidationRejectsNullServices()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => AshlarServiceCollectionExtensions.AddAshlarConfigurationValidation(null!));

        Assert.That(exception.ParamName, Is.EqualTo("services"));
    }

    [Test]
    public void AddAshlarIdentityRegistersConfigurationValidator()
    {
        var services = new ServiceCollection();

        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();

        Assert.That(provider.GetRequiredService<IAshlarConfigurationValidator>(), Is.TypeOf<AshlarConfigurationValidator>());
    }

    [Test]
    public async Task ValidatorHonorsCancellationBeforeRunningChecks()
    {
        var services = new ServiceCollection();
        services.AddScoped<IAshlarConfigurationValidator, AshlarConfigurationValidator>();
        services.AddSingleton<IAshlarConfigurationCheck, EmptyConfigurationCheck>();
        using var provider = services.BuildServiceProvider();
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await provider.GetRequiredService<IAshlarConfigurationValidator>().ValidateAsync(cancellation.Token));
    }

    [Test]
    public void CoreCheckRejectsNullServiceProvider()
    {
        var check = new AshlarCoreConfigurationCheck();

        var exception = Assert.Throws<ArgumentNullException>(() => _ = check.CheckAsync(null!).AsTask().GetAwaiter().GetResult());

        Assert.That(exception.ParamName, Is.EqualTo("serviceProvider"));
    }

    [Test]
    public void CoreCheckHonorsCancellation()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var check = new AshlarCoreConfigurationCheck();

        Assert.Throws<OperationCanceledException>(() => _ = check.CheckAsync(provider, cancellation.Token).AsTask().GetAwaiter().GetResult());
    }

    [Test]
    public async Task CoreCheckDoesNotThrowWhenRootProviderRejectsScopedTransactionProviderResolution()
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        using var provider = services.BuildServiceProvider(validateScopes: true);
        var check = new AshlarCoreConfigurationCheck();

        var issues = await check.CheckAsync(provider);

        Assert.That(issues, Has.Some.Matches<AshlarConfigurationIssue>(issue =>
            issue.Code == AshlarConfigurationIssueCodes.NullTransactionProvider));
    }

    [Test]
    public void CoreCheckDoesNotSwallowTransactionProviderActivationFailures()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAshlarTransactionProvider>(_ => throw new InvalidOperationException("custom transaction failure"));
        using var provider = services.BuildServiceProvider();
        var check = new AshlarCoreConfigurationCheck();

        var exception = Assert.ThrowsAsync<InvalidOperationException>(async () => await check.CheckAsync(provider).AsTask());

        Assert.That(exception?.Message, Is.EqualTo("custom transaction failure"));
    }

    [Test]
    public async Task CoreCheckSupportsServiceProvidersWithoutScopeFactory()
    {
        var provider = new FallbackServiceProvider(typeof(IUserRepository), Mock.Of<IUserRepository>());
        var check = new AshlarCoreConfigurationCheck();

        var issues = await check.CheckAsync(provider);

        AssertIssue(issues, AshlarConfigurationIssueCodes.NullTransactionProvider, AshlarConfigurationIssueSeverity.Warning);
    }

    [Test]
    public void IsServiceRegisteredFallsBackWhenProviderDoesNotExposeIsService()
    {
        var provider = new FallbackServiceProvider(typeof(IUserRepository), Mock.Of<IUserRepository>());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.IsServiceRegistered<IUserRepository>(), Is.True);
            Assert.That(provider.IsServiceRegistered<ICredentialRepository>(), Is.False);
        }
    }

    [Test]
    public void IsServiceRegisteredTreatsInvalidOperationFromFallbackProviderAsRegistered()
    {
        var provider = new ThrowingFallbackServiceProvider();

        Assert.That(provider.IsServiceRegistered<IUserRepository>(), Is.True);
    }

    [Test]
    public void IsServiceRegisteredRejectsNullServiceProvider()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => _ = AshlarConfigurationServiceProviderExtensions.IsServiceRegistered<IUserRepository>(null!));

        Assert.That(exception.ParamName, Is.EqualTo("serviceProvider"));
    }

    [Test]
    public void IsServiceRegisteredRejectsNullServiceType()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<ArgumentNullException>(() => _ = provider.IsServiceRegistered(null!));

        Assert.That(exception.ParamName, Is.EqualTo("serviceType"));
    }

    private static AshlarConfigurationIssue AssertIssue(
        AshlarConfigurationValidationResult result,
        string code,
        AshlarConfigurationIssueSeverity severity)
    {
        var issue = result.Issues.FirstOrDefault(item =>
            item.Code == code
            && item.Severity == severity
            && !string.IsNullOrWhiteSpace(item.Message)
            && !string.IsNullOrWhiteSpace(item.Recommendation)
            && !string.IsNullOrWhiteSpace(item.Component));

        Assert.That(issue, Is.Not.Null);
        return issue!;
    }

    private static List<AshlarConfigurationIssue> AssertIssues(
        AshlarConfigurationValidationResult result,
        string code,
        AshlarConfigurationIssueSeverity severity)
    {
        var issues = result.Issues
            .Where(item =>
                item.Code == code
                && item.Severity == severity
                && !string.IsNullOrWhiteSpace(item.Message)
                && !string.IsNullOrWhiteSpace(item.Recommendation)
                && !string.IsNullOrWhiteSpace(item.Component))
            .ToList();

        Assert.That(issues, Is.Not.Empty);
        return issues;
    }

    private static AshlarConfigurationIssue AssertIssue(
        IReadOnlyList<AshlarConfigurationIssue> issues,
        string code,
        AshlarConfigurationIssueSeverity severity)
    {
        var issue = issues.FirstOrDefault(item =>
            item.Code == code
            && item.Severity == severity
            && !string.IsNullOrWhiteSpace(item.Message)
            && !string.IsNullOrWhiteSpace(item.Recommendation)
            && !string.IsNullOrWhiteSpace(item.Component));

        Assert.That(issue, Is.Not.Null);
        return issue!;
    }

    private static void RegisterCallbackFlow(IServiceCollection services, string flow)
    {
        switch (flow)
        {
            case "magic-link":
                services.AddSingleton(Mock.Of<IMagicLinkSignInService>());
                break;
            case "email-verification":
                services.AddSingleton(Mock.Of<IEmailVerificationService>());
                break;
            case "email-change":
                services.AddSingleton(Mock.Of<IEmailChangeService>());
                break;
            case "invitation":
                services.AddSingleton(Mock.Of<IInvitationService>());
                break;
            case "password-reset":
                services.AddSingleton(Mock.Of<IPasswordResetService>());
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(flow), flow, "Unknown callback flow.");
        }
    }

    private sealed class StubConfigurationCheck(params AshlarConfigurationIssue[] issues) : IAshlarConfigurationCheck
    {
        public ValueTask<IReadOnlyList<AshlarConfigurationIssue>> CheckAsync(
            IServiceProvider serviceProvider,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IReadOnlyList<AshlarConfigurationIssue>>(issues);
        }
    }

    private sealed class EmptyConfigurationCheck : IAshlarConfigurationCheck
    {
        public ValueTask<IReadOnlyList<AshlarConfigurationIssue>> CheckAsync(
            IServiceProvider serviceProvider,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IReadOnlyList<AshlarConfigurationIssue>>([]);
        }
    }

    private sealed class CustomEmailSender : IEmailSender
    {
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class CustomPersistentSecurityEventSink : IPersistentSecurityEventSink
    {
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class CustomSecurityEventHandler : ISecurityEventHandler
    {
        public Task HandleAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class CustomSecurityNotificationSuppressionStore : ISecurityNotificationSuppressionStore
    {
        public bool ShouldSend(SecurityNotification notification, TimeSpan cooldown, DateTimeOffset now) => true;
    }

    private sealed class CustomAuthenticationRateLimiter : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new RateLimitDecision
            {
                Status = RateLimitStatus.Allowed,
                Remaining = 1,
                WindowResetAt = DateTimeOffset.MaxValue,
            });
        }
    }

    private sealed class CustomTransactionProvider : IAshlarTransactionProvider
    {
        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IAshlarTransaction>(new CustomTransaction());
        }
    }

    private sealed class CustomTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public void OnCommitted(Func<CancellationToken, Task> action)
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FallbackServiceProvider(Type serviceType, object service) : IServiceProvider
    {
        public object? GetService(Type requestedServiceType)
        {
            return requestedServiceType == serviceType ? service : null;
        }
    }

    private sealed class ThrowingFallbackServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType)
        {
            throw new InvalidOperationException("Service is registered but cannot be activated.");
        }
    }
}
