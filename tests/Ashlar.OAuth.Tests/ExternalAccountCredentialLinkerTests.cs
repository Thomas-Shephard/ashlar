using Ashlar.Testing;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Abstractions.Transactions;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Identity.Models.Credentials;
using Ashlar.Identity.Models.Sessions;
using Ashlar.Identity.Models.Tenants;
using Moq;

namespace Ashlar.OAuth.Tests;

internal sealed class ExternalAccountCredentialLinkerTests
{
    [Test]
    public void ConstructorRejectsFanOutBoundToAnotherTransactionProvider()
    {
        var persistent = new PersistentSink();
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();
        var transactions = Transactions(persistent, users, credentials);
        var otherTransactions = Transactions(persistent, users, credentials);

        Assert.Throws<ArgumentException>(() => CreateService(users, credentials, transactions.Provider, new SecurityEventFanOutSink(persistent, transactionProvider: otherTransactions.Provider)));
    }

    [Test]
    public void ConstructorRejectsFanOutWithoutDurableWork()
    {
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();
        var transactions = Transactions(users, credentials);

        Assert.Throws<ArgumentException>(() => CreateService(users, credentials, transactions.Provider, new SecurityEventFanOutSink(transactionProvider: transactions.Provider)));
    }

    [Test]
    public void ConstructorRejectsRepositoriesOutsideTheDurableComposition()
    {
        var persistent = new PersistentSink();
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();

        foreach (var transactions in new[]
        {
            Transactions(persistent, credentials),
            Transactions(persistent, users)
        })
        {
            var fanOut = new SecurityEventFanOutSink(persistent, transactionProvider: transactions.Provider);
            Assert.Throws<ArgumentException>(() => CreateService(users, credentials, transactions.Provider, fanOut));
        }
    }

    [Test]
    public void ConstructorRejectsNullRequiredDependencies()
    {
        var persistent = new PersistentSink();
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();
        var transactions = Transactions(persistent, users, credentials);
        var events = new SecurityEventFanOutSink(persistent, transactionProvider: transactions.Provider);
        var validator = new ActiveSessionFreshProofValidator(Mock.Of<IAuthenticationSessionRepository>(), TimeProvider.System);

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => new ExternalAccountCredentialLinker(null!, credentials, validator, transactions.Provider, events));
            Assert.Throws<ArgumentNullException>(() => new ExternalAccountCredentialLinker(users, null!, validator, transactions.Provider, events));
            Assert.Throws<ArgumentNullException>(() => new ExternalAccountCredentialLinker(users, credentials, null!, transactions.Provider, events));
            Assert.Throws<ArgumentNullException>(() => new ExternalAccountCredentialLinker(users, credentials, validator, null!, events));
        }
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncRejectsMissingAuditBeforeMutation()
    {
        var persistent = new PersistentSink();
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();
        var transactions = Transactions(persistent, users, credentials);
        var service = CreateService(users, credentials, transactions.Provider, new SecurityEventFanOutSink(persistent, transactionProvider: transactions.Provider));
        var assertion = Mock.Of<IAuthenticationAssertion>();
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(p => p.Key).Returns(new AuthenticationProviderKey(ProviderType.OAuth, "github"));

        var result = await service.LinkExternalAccountCredentialAsync(new ExternalAccountCredentialLinkRequest(
            Guid.NewGuid(), assertion, provider.Object, null, null, TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        transactions.Raw.Verify(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncRejectsNonExternalProvidersAndInvalidProofsBeforeMutation()
    {
        var persistent = new PersistentSink();
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();
        var transactions = Transactions(persistent, users, credentials);
        var service = CreateService(users, credentials, transactions.Provider, new SecurityEventFanOutSink(persistent, transactionProvider: transactions.Provider));
        var assertion = Mock.Of<IAuthenticationAssertion>();
        var localProvider = Provider(ProviderType.Local, "password", "key");
        var oauthProvider = Provider(ProviderType.OAuth, "github", "key");

        var nonExternal = await service.LinkExternalAccountCredentialAsync(new ExternalAccountCredentialLinkRequest(
            Guid.NewGuid(), assertion, localProvider.Object, null, null, TenantContext.Global, new AuditContext()));
        var invalidProof = await service.LinkExternalAccountCredentialAsync(new ExternalAccountCredentialLinkRequest(
            Guid.NewGuid(), assertion, oauthProvider.Object, null, null, TenantContext.Global, new AuditContext()));
        var oidcProvider = Provider(ProviderType.Oidc, "google", "key");
        var oidcInvalidProof = await service.LinkExternalAccountCredentialAsync(new ExternalAccountCredentialLinkRequest(
            Guid.NewGuid(), assertion, oidcProvider.Object, null, null, TenantContext.Global, new AuditContext()));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(nonExternal.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(invalidProof.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
            Assert.That(oidcInvalidProof.FailureCode, Is.EqualTo(AshlarFailureCodes.StepUpRequired));
        }
        transactions.Raw.Verify(p => p.BeginTransactionAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [TestCase("missing", AshlarFailureCodes.UserNotFoundValue)]
    [TestCase("mismatch", AshlarFailureCodes.TenantMismatchValue)]
    [TestCase("empty-key", AshlarFailureCodes.InvalidProviderKeyValue)]
    [TestCase("self", AshlarFailureCodes.AlreadyLinkedToSelfValue)]
    [TestCase("other", AshlarFailureCodes.AlreadyLinkedToOtherValue)]
    [TestCase("conflict", AshlarFailureCodes.AlreadyLinkedToOtherValue)]
    public async Task LinkExternalAccountCredentialAsyncAuditsMutationFailures(string scenario, string expectedFailure)
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var users = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var transaction = new Mock<IAshlarTransaction>();
        var events = new PersistentSink();
        var transactions = Transactions(events, users.Object, credentials.Object);
        transactions.Raw.Setup(provider => provider.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);
        var service = CreateService(users.Object, credentials.Object, transactions.Provider, events, userId, tenantId);
        var provider = Provider(ProviderType.OAuth, "github", scenario == "empty-key" ? " " : "github-subject");

        if (scenario != "missing")
        {
            users.Setup(repository => repository.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(UserFor(userId, scenario == "mismatch" ? Guid.NewGuid() : tenantId));
        }
        if (scenario is "self" or "other")
        {
            users.Setup(repository => repository.GetUserByProviderKeyAsync(ProviderType.OAuth, "github", "github-subject", It.IsAny<CancellationToken>()))
                .ReturnsAsync(UserFor(scenario == "self" ? userId : Guid.NewGuid(), null));
        }
        if (scenario == "conflict")
        {
            credentials.Setup(repository => repository.CreateOrReplaceCredentialAsync(It.IsAny<UserCredential>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new CredentialProviderKeyConflictException());
        }

        var result = await service.LinkExternalAccountCredentialAsync(Request(userId, tenantId, provider.Object));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.FailureCode?.Value, Is.EqualTo(expectedFailure));
            Assert.That(events.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Failure));
            Assert.That(events.Events.Single().FailureReason, Is.EqualTo(expectedFailure));
        }
        transaction.Verify(value => value.CommitAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task LinkExternalAccountCredentialAsyncCreatesCredentialAndAuditsSuccess()
    {
        var userId = Guid.NewGuid();
        var tenantId = Guid.NewGuid();
        var users = new Mock<IUserRepository>();
        var credentials = new Mock<ICredentialRepository>();
        var events = new PersistentSink();
        var transactions = Transactions(events, users.Object, credentials.Object);
        var provider = Provider(ProviderType.Oidc, "google", "subject");
        users.Setup(repository => repository.GetUserByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(UserFor(userId, tenantId));

        var service = CreateService(users.Object, credentials.Object, transactions.Provider, events, userId, tenantId);
        var result = await service.LinkExternalAccountCredentialAsync(Request(userId, tenantId, provider.Object, "metadata"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(events.Events.Single().Outcome, Is.EqualTo(SecurityEventOutcomes.Success));
            Assert.That(events.Events.Single().Properties, Contains.Key("credential_id"));
        }
        credentials.Verify(repository => repository.CreateOrReplaceCredentialAsync(It.Is<UserCredential>(credential =>
            credential.UserId == userId && credential.ProviderType == provider.Object.Key.Type && credential.ProviderName == provider.Object.Key.Name && credential.Metadata == "metadata"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void LinkExternalAccountCredentialAsyncRejectsNullRequestAndRequiredMembers()
    {
        var persistent = new PersistentSink();
        var users = Mock.Of<IUserRepository>();
        var credentials = Mock.Of<ICredentialRepository>();
        var transactions = Transactions(persistent, users, credentials);
        var service = CreateService(users, credentials, transactions.Provider, new SecurityEventFanOutSink(persistent, transactionProvider: transactions.Provider));
        var provider = Provider(ProviderType.OAuth, "github", "subject");
        var request = Request(Guid.NewGuid(), Guid.NewGuid(), provider.Object);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(request with { Assertion = null! }));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(request with { Provider = null! }));
            Assert.ThrowsAsync<ArgumentNullException>(() => service.LinkExternalAccountCredentialAsync(request with { Tenant = null! }));
        }
    }

    private static ExternalAccountCredentialLinker CreateService(
        AshlarDurableTransactionProvider transactions,
        SecurityEventFanOutSink events) =>
        CreateService(Mock.Of<IUserRepository>(), Mock.Of<ICredentialRepository>(), transactions, events);

    private static ExternalAccountCredentialLinker CreateService(
        IUserRepository users,
        ICredentialRepository credentials,
        AshlarDurableTransactionProvider transactions,
        SecurityEventFanOutSink events) =>
        new(users, credentials,
            new ActiveSessionFreshProofValidator(Mock.Of<IAuthenticationSessionRepository>(), TimeProvider.System),
            transactions, events);

    private static ExternalAccountCredentialLinker CreateService(
        IUserRepository users,
        ICredentialRepository credentials,
        AshlarDurableTransactionProvider transactions,
        PersistentSink events,
        Guid userId,
        Guid tenantId)
    {
        var sessionId = Guid.NewGuid();
        var sessions = new Mock<IAuthenticationSessionRepository>();
        sessions.Setup(repository => repository.GetSessionAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthenticationSession
            {
                Id = sessionId,
                UserId = userId,
                TenantId = tenantId,
                TokenHash = "hash",
                CreatedAt = DateTimeOffset.UtcNow,
                AuthenticatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
            });
        return new ExternalAccountCredentialLinker(users, credentials,
            new ActiveSessionFreshProofValidator(sessions.Object, TimeProvider.System), transactions,
            new SecurityEventFanOutSink(events, transactionProvider: transactions));
    }

    private static ExternalAccountCredentialLinkRequest Request(Guid userId, Guid tenantId, IAuthenticationProvider provider, string? metadata = null)
    {
        var sessionId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        return new ExternalAccountCredentialLinkRequest(userId, Mock.Of<IAuthenticationAssertion>(), provider,
            ExternalAccountLinkServiceTestExtensions.CreateProof(userId, new TenantContext(tenantId), sessionId, "external-account-linking", now),
            sessionId, new TenantContext(tenantId), new AuditContext(userId, "127.0.0.1", "tests", "correlation"), metadata);
    }

    private static Mock<IAuthenticationProvider> Provider(ProviderType type, string name, string key)
    {
        var provider = new Mock<IAuthenticationProvider>();
        provider.SetupGet(value => value.Key).Returns(new AuthenticationProviderKey(type, name));
        provider.Setup(value => value.GetProviderKey(It.IsAny<IAuthenticationAssertion>(), It.IsAny<Guid>())).Returns(key);
        return provider;
    }

    private static TransactionComposition Transactions(params object[] participants)
    {
        var transaction = new Mock<IAshlarTransaction>();
        var raw = new Mock<IAshlarTransactionProvider>();
        raw.Setup(provider => provider.BeginTransactionAsync(It.IsAny<CancellationToken>())).ReturnsAsync(transaction.Object);
        return new(raw, DurableTransactionComposition.Create(raw.Object, participants));
    }

    private sealed record TransactionComposition(Mock<IAshlarTransactionProvider> Raw, AshlarDurableTransactionProvider Provider);

    private static ITenantUser UserFor(Guid userId, Guid? tenantId)
    {
        var user = new Mock<ITenantUser>();
        user.SetupGet(value => value.Id).Returns(userId);
        user.SetupGet(value => value.TenantId).Returns(tenantId);
        return user.Object;
    }

    private sealed class PersistentSink : IPersistentSecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];

        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
