using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Auditing;
using Ashlar.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Operational;

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

    protected static IIdentityRepository GetIdentityRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IIdentityRepository>();
    }

    protected static IBootstrapStateRepository GetBootstrapStateRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IBootstrapStateRepository>();
    }

    protected static IInvitationRepository GetInvitationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IInvitationRepository>();
    }

    protected static IAuthenticationSessionRepository GetAuthenticationSessionRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationSessionRepository>();
    }

    protected static IAuthenticationHandshakeRepository GetAuthenticationHandshakeRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationHandshakeRepository>();
    }

    protected static IAuthorizationGrantRepository GetAuthorizationGrantRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();
    }

    protected static ISecurityEventSink GetSecurityEventSink(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventSink>();
    }

    protected static IUserSecurityEventSummaryRepository GetUserSecurityEventSummaryRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IUserSecurityEventSummaryRepository>();
    }

    protected static IPasskeyChallengeRepository GetPasskeyChallengeRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IPasskeyChallengeRepository>();
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
        return serviceProvider.GetService<IAshlarTransactionProvider>();
    }

    protected static async Task<AshlarUser> CreateUserAsync(
        IIdentityRepository repository,
        string? email = null,
        Guid? tenantId = null,
        bool isActive = true)
    {
        var user = new AshlarUser
        {
            Id = Guid.NewGuid(),
            Email = email ?? $"{Guid.NewGuid():N}@example.com",
            Name = "Test User",
            IsActive = isActive,
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
