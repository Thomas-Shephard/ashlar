using Ashlar.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.ProviderContractTests.Messaging;

namespace Ashlar.ProviderContractTests;

internal abstract class ProviderContractFixture
{
    private IServiceProvider? _serviceProvider;

    [SetUp]
    public async Task SetUpProviderContractFixture()
    {
        _serviceProvider = await CreateInitializedServiceProviderAsync();
    }

    [TearDown]
    public async Task TearDownProviderContractFixture()
    {
        var serviceProvider = _serviceProvider;
        _serviceProvider = null;

        if (serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
        else if (serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }

        await CleanupInitializedServiceProviderAsync();
    }

    protected abstract Task<IServiceProvider> CreateInitializedServiceProviderAsync();

    protected virtual Task CleanupInitializedServiceProviderAsync()
    {
        return Task.CompletedTask;
    }

    protected AsyncServiceScope CreateAsyncScope()
    {
        return Services.CreateAsyncScope();
    }

    protected static IUserRepository GetUserRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IUserRepository>();
    }

    protected static ICredentialRepository GetCredentialRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<ICredentialRepository>();
    }

    protected static IAccountLockoutRepository GetAccountLockoutRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IAccountLockoutRepository>();
    }

    protected static IUserAdministrationRepository GetUserAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IUserAdministrationRepository>();
    }

    protected static ICredentialAdministrationRepository GetCredentialAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ICredentialAdministrationRepository>();
    }

    protected static IBootstrapStateRepository GetBootstrapStateRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IBootstrapStateRepository>();
    }

    protected static IInvitationRepository GetInvitationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IInvitationRepository>();
    }

    protected static IAuthenticationSessionRepository GetAuthenticationSessionRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IAuthenticationSessionRepository>();
    }

    protected static IRememberedMfaDeviceRepository GetRememberedMfaDeviceRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IRememberedMfaDeviceRepository>();
    }

    protected static IAuthenticationSessionAdministrationRepository GetAuthenticationSessionAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationSessionAdministrationRepository>();
    }

    protected static IAuthenticationHandshakeRepository GetAuthenticationHandshakeRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IAuthenticationHandshakeRepository>();
    }

    protected static IAuthorizationGrantRepository GetAuthorizationGrantRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IAuthorizationGrantRepository>();
    }

    protected static IAuthorizationGrantAdministrationRepository GetAuthorizationGrantAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthorizationGrantAdministrationRepository>();
    }

    protected static ISecurityEventSink GetSecurityEventSink(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventSink>();
    }

    protected static IPersistentSecurityEventSink GetPersistentSecurityEventSink(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IPersistentSecurityEventSink>();
    }

    protected static IUserSecurityEventSummaryRepository GetUserSecurityEventSummaryRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IUserSecurityEventSummaryRepository>();
    }

    protected static ISecurityEventAdministrationRepository GetSecurityEventAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventAdministrationRepository>();
    }

    protected static IPasskeyChallengeRepository GetPasskeyChallengeRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IPasskeyChallengeRepository>();
    }

    protected static IAuthenticationRateLimiter GetAuthenticationRateLimiter(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationRateLimiter>();
    }

    protected static IAshlarCleanupService GetCleanupService(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAshlarCleanupService>();
    }

    protected static IAshlarTransactionProvider? GetTransactionProvider(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetService<AshlarDurableTransactionProvider>();
    }

    protected static IEmailSender GetEmailSender(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailSender>();
    }

    protected static IEmailOutboxDispatcher GetEmailOutboxDispatcher(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailOutboxDispatcher>();
    }

    protected static IEmailOutboxDiagnostics GetEmailOutboxDiagnostics(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailOutboxDiagnostics>();
    }

    protected static IAshlarSecurityEventWebhookEnqueuer GetSecurityEventWebhookEnqueuer(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredAshlarProviderService<IAshlarSecurityEventWebhookEnqueuer>();
    }

    protected static IAshlarSecurityEventWebhookOutboxBrowser GetSecurityEventWebhookOutboxBrowser(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>();
    }

    protected static IAshlarSecurityEventWebhookOutboxOperations GetSecurityEventWebhookOutboxOperations(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookOutboxOperations>();
    }

    protected static ISecurityEventWebhookOutboxDiagnostics GetSecurityEventWebhookOutboxDiagnostics(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>();
    }

    protected static RecordingEmailTransport GetRecordingEmailTransport(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<RecordingEmailTransport>();
    }

    protected virtual Task AdvanceEmailOutboxTimeAsync(TimeSpan offset)
    {
        return Task.CompletedTask;
    }

    protected static async Task<AshlarUser> CreateUserAsync(
        IUserRepository repository,
        string? email = null,
        Guid? tenantId = null,
        UserAccountState AccountState = UserAccountState.Active)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email ?? $"{Guid.NewGuid():N}@example.com",
            Name = "Test User",
            AccountState = AccountState,
            TenantId = tenantId
        };

        await repository.CreateUserAsync(user);
        return user;
    }

    protected static UserCredential CreateCredential(
        Guid userId,
        ProviderType providerType,
        string providerName,
        string? providerKey = null)
    {
        return new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = providerType,
            ProviderName = providerName,
            ProviderKey = providerKey ?? $"{providerName}-{Guid.NewGuid():N}",
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = DateTimeOffset.UtcNow,
            Status = CredentialStatus.Active
        };
    }

    protected virtual Task<IReadOnlyList<SecurityEventStorageRecord>> ReadSecurityEventStorageRecordsAsync()
    {
        throw new NotSupportedException("This provider contract fixture does not expose security event storage records.");
    }

    private IServiceProvider Services => _serviceProvider ?? throw new InvalidOperationException("Provider contract fixture has not been initialized.");
}
