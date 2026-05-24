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

    private static void AssertIssue(
        AshlarConfigurationValidationResult result,
        string code,
        AshlarConfigurationIssueSeverity severity)
    {
        Assert.That(result.Issues, Has.Some.Matches<AshlarConfigurationIssue>(issue =>
            issue.Code == code
            && issue.Severity == severity
            && !string.IsNullOrWhiteSpace(issue.Message)
            && !string.IsNullOrWhiteSpace(issue.Recommendation)
            && !string.IsNullOrWhiteSpace(issue.Component)));
    }

    private static void AssertIssue(
        IReadOnlyList<AshlarConfigurationIssue> issues,
        string code,
        AshlarConfigurationIssueSeverity severity)
    {
        Assert.That(issues, Has.Some.Matches<AshlarConfigurationIssue>(issue =>
            issue.Code == code
            && issue.Severity == severity
            && !string.IsNullOrWhiteSpace(issue.Message)
            && !string.IsNullOrWhiteSpace(issue.Recommendation)
            && !string.IsNullOrWhiteSpace(issue.Component)));
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
