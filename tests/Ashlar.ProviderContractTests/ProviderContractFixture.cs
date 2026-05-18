using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Microsoft.Extensions.DependencyInjection;

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

    private IServiceProvider Services => _serviceProvider ?? throw new InvalidOperationException("Provider contract fixture has not been initialized.");
}
