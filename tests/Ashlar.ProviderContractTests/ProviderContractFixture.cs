using Ashlar.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.ProviderContractTests.Messaging;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Features.Mfa;
using Ashlar.Security.Tokens;
using System.Runtime.ExceptionServices;

namespace Ashlar.ProviderContractTests;

/// <summary>
/// Provides lifecycle management and shared infrastructure for provider contract suites.
/// </summary>
public abstract class ProviderContractFixture
{
    private IServiceProvider? _serviceProvider;

    /// <summary>
    /// Creates the initialized provider services before each contract test.
    /// </summary>
    /// <exception cref="AggregateException">Provider setup and its compensating cleanup both fail.</exception>
    /// <exception cref="Exception">Provider setup fails.</exception>
    [SetUp]
    public async Task SetUpProviderContractFixture()
    {
        try
        {
            _serviceProvider = await CreateInitializedServiceProviderAsync();
        }
        catch (Exception setupException)
        {
            try
            {
                await CleanupInitializedServiceProviderAsync();
            }
            catch (Exception cleanupException)
            {
                throw new AggregateException("Provider contract setup and cleanup both failed.", setupException, cleanupException);
            }

            throw;
        }
    }

    /// <summary>
    /// Disposes the provider services and invokes provider cleanup after each contract test.
    /// </summary>
    /// <exception cref="AggregateException">Provider disposal and cleanup both fail.</exception>
    [TearDown]
    public async Task TearDownProviderContractFixture()
    {
        var serviceProvider = _serviceProvider;
        _serviceProvider = null;
        Exception? disposalException = null;

        try
        {
            if (serviceProvider is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync();
            }
            else if (serviceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        catch (Exception exception)
        {
            disposalException = exception;
        }

        try
        {
            await CleanupInitializedServiceProviderAsync();
        }
        catch (Exception cleanupException) when (disposalException is not null)
        {
            throw new AggregateException("Provider contract disposal and cleanup both failed.", disposalException, cleanupException);
        }

        if (disposalException is not null)
        {
            ExceptionDispatchInfo.Capture(disposalException).Throw();
        }
    }

    /// <summary>
    /// Creates and initializes the service provider used by one contract test.
    /// </summary>
    /// <returns>The initialized service provider.</returns>
    protected abstract Task<IServiceProvider> CreateInitializedServiceProviderAsync();

    /// <summary>
    /// Cleans up provider-owned resources created for one contract test.
    /// </summary>
    /// <returns>A task that completes when cleanup has finished.</returns>
    protected virtual Task CleanupInitializedServiceProviderAsync()
    {
        return Task.CompletedTask;
    }

    private protected AsyncServiceScope CreateAsyncScope()
    {
        return Services.CreateAsyncScope();
    }

    private protected static IUserRepository GetUserRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IUserRepository>();
    }

    private protected static ICredentialRepository GetCredentialRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ICredentialRepository>();
    }

    private protected static IAccountLockoutRepository GetAccountLockoutRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAccountLockoutRepository>();
    }

    private protected static IUserAdministrationRepository GetUserAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IUserAdministrationRepository>();
    }

    private protected static ICredentialAdministrationRepository GetCredentialAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ICredentialAdministrationRepository>();
    }

    private protected static IBootstrapStateRepository GetBootstrapStateRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IBootstrapStateRepository>();
    }

    private protected static IInvitationRepository GetInvitationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IInvitationRepository>();
    }

    private protected static IAuthenticationSessionRepository GetAuthenticationSessionRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationSessionRepository>();
    }

    private protected static IRememberedMfaDeviceRepository GetRememberedMfaDeviceRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IRememberedMfaDeviceRepository>();
    }

    private protected static IAuthenticationSessionAdministrationRepository GetAuthenticationSessionAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationSessionAdministrationRepository>();
    }

    private protected static IAuthenticationHandshakeRepository GetAuthenticationHandshakeRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationHandshakeRepository>();
    }

    private protected static IAuthorizationGrantRepository GetAuthorizationGrantRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();
    }

    private protected static IAuthorizationGrantAdministrationRepository GetAuthorizationGrantAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthorizationGrantAdministrationRepository>();
    }

    private protected static ISecurityEventSink GetSecurityEventSink(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventSink>();
    }

    private protected static IPersistentSecurityEventSink GetPersistentSecurityEventSink(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IPersistentSecurityEventSink>();
    }

    private protected static IUserSecurityEventSummaryRepository GetUserSecurityEventSummaryRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IUserSecurityEventSummaryRepository>();
    }

    private protected static ISecurityEventAdministrationRepository GetSecurityEventAdministrationRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventAdministrationRepository>();
    }

    private protected static IPasskeyChallengeRepository GetPasskeyChallengeRepository(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IPasskeyChallengeRepository>();
    }

    private protected static IAuthenticationRateLimiter GetAuthenticationRateLimiter(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAuthenticationRateLimiter>();
    }

    private protected static IAshlarTransactionProvider? GetTransactionProvider(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetService<AshlarDurableTransactionProvider>();
    }

    private protected static IEmailSender GetEmailSender(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailSender>();
    }

    private protected static IEmailOutboxDiagnostics GetEmailOutboxDiagnostics(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IEmailOutboxDiagnostics>();
    }

    private protected static IAshlarSecurityEventWebhookEnqueuer GetSecurityEventWebhookEnqueuer(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookEnqueuer>();
    }

    private protected static IAshlarSecurityEventWebhookOutboxBrowser GetSecurityEventWebhookOutboxBrowser(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookOutboxBrowser>();
    }

    private protected static IAshlarSecurityEventWebhookOutboxOperations GetSecurityEventWebhookOutboxOperations(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<IAshlarSecurityEventWebhookOutboxOperations>();
    }

    private protected static ISecurityEventWebhookOutboxDiagnostics GetSecurityEventWebhookOutboxDiagnostics(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<ISecurityEventWebhookOutboxDiagnostics>();
    }

    private protected static RecordingEmailTransport GetRecordingEmailTransport(IServiceProvider serviceProvider)
    {
        return serviceProvider.GetRequiredService<RecordingEmailTransport>();
    }

    private protected static async Task<AshlarUser> CreateUserAsync(
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

    private protected static UserCredential CreateCredential(
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

    private protected static async Task<FreshMfaVerificationProof> CreateFreshMfaProofAsync(
        IServiceProvider services,
        AuthenticationSession session,
        string token,
        string purpose)
    {
        await GetAuthenticationSessionRepository(services).CreateSessionAsync(session);
        var validation = await services.GetRequiredService<IAuthenticationSessionService>().ValidateSessionAsync(token);
        var validatedSession = validation.ValidatedSession
            ?? throw new InvalidOperationException("The contract actor session could not be validated.");
        return services.GetRequiredService<StepUpAuthenticationService>()
            .CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.FromMinutes(5)), purpose)
            .Value ?? throw new InvalidOperationException("The contract actor MFA proof could not be created.");
    }

    private protected static string HashToken(IServiceProvider services, string token) =>
        services.GetRequiredService<ISecureTokenHasher>().HashToken(token);

    private IServiceProvider Services => _serviceProvider ?? throw new InvalidOperationException("Provider contract fixture has not been initialized.");
}
