using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Abstractions.Tenancy;
using Ashlar.Identity.Features.Mfa;
using Ashlar.ProviderContracts.DependencyInjection;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.ProviderContractTests.Testing;

internal sealed class AccountSecurityActorTestContext
{
    internal AccountSecurityActorTestContext(DateTimeOffset now, string proofPurpose)
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var users = new StubUserRepository();
        users.User = new AshlarUser { Id = userId, DisplayEmail = $"{userId:N}@example.test", AccountState = UserAccountState.Active };

        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddAshlarDurableTransactionProvider<TestTransactionProvider>("Contract proof");
        services.AddAshlarProviderScoped<TestTransactionProvider, IUserRepository>("Contract proof", _ => users);
        services.AddAshlarProviderScoped<TestTransactionProvider, IAuthenticationSessionRepository>("Contract proof", _ => Sessions);
        services.AddAshlarProviderScoped<TestTransactionProvider, IPersistentSecurityEventSink>("Contract proof", _ => new NullAuditSink());
        services.AddAshlarDurableTransactionParticipant<IUserRepository>();
        services.AddAshlarDurableTransactionParticipant<IAuthenticationSessionRepository>();
        services.AddAshlarDurableTransactionParticipant<IPersistentSecurityEventSink>();
        services.AddSingleton<IAccountSecurityOperationAuthorizer>(Authorizer);
        services.AddSingleton<TimeProvider>(new FixedTimeProvider(now));
        using var provider = services.BuildServiceProvider();
        Sessions.Session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = provider.GetRequiredService<ISecureTokenHasher>().HashToken(token),
            CreatedAt = now,
            AdditionalVerificationAt = now,
            ExpiresAt = now.AddHours(1)
        };
        var validated = provider.GetRequiredService<IAuthenticationSessionService>().ValidateSessionAsync(token).GetAwaiter().GetResult();
        var validatedSession = validated.ValidatedSession
            ?? throw new InvalidOperationException("The webhook contract actor session could not be validated.");
        var proof = provider.GetRequiredService<StepUpAuthenticationService>()
            .CreateFreshMfaProof(validatedSession, new StepUpRequirement(TimeSpan.FromMinutes(5)), proofPurpose).Value
            ?? throw new InvalidOperationException("The webhook contract actor MFA proof could not be created.");
        Actor = new AccountSecurityActorContext(userId, TenantContext.Global, sessionId, proof, new AuditContext(userId));
        Authorizer.Authorized = true;
    }

    internal AccountSecurityActorContext Actor { get; }
    public StubAuthenticationSessionRepository Sessions { get; } = new();
    public StubAccountSecurityOperationAuthorizer Authorizer { get; } = new();
}

internal sealed class StubAccountSecurityOperationAuthorizer : IAccountSecurityOperationAuthorizer
{
    public bool Authorized { get; set; }

    public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Authorized);
}

internal sealed class StubAuthenticationSessionRepository : IAuthenticationSessionRepository
{
    internal AuthenticationSession? Session { get; set; }
    internal List<AuthenticationSession> AdditionalSessions { get; } = [];

    public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Session?.Id == sessionId ? Session : AdditionalSessions.SingleOrDefault(session => session.Id == sessionId));

    public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default) { Session = session; return Task.CompletedTask; }
    public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) => Task.FromResult(Session?.TokenHash == tokenHash ? Session : null);
    public Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default) => Task.FromResult(true);
    public Task<AuthenticationSession?> MarkStepUpVerifiedAsync(Guid sessionId, Guid userId, DateTimeOffset verifiedAt, AuthenticationProviderKey verifiedProvider, string verifiedFactor, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}

internal sealed class StubUserRepository : IUserRepository
{
    internal IUser? User { get; set; }
    public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default) { User = user; return Task.CompletedTask; }
    public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default) { User = user; return Task.CompletedTask; }
    public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult(User?.Id == userId ? User : null);
    public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
    public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(null);
}

internal sealed class NullAuditSink : IPersistentSecurityEventSink
{
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

internal sealed class TestTransactionProvider : IAshlarTransactionProvider
{
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) => Task.FromResult<IAshlarTransaction>(new TestTransaction());
}

internal sealed class TestTransaction : IAshlarTransaction
{
    public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public void OnCommitted(Func<CancellationToken, Task> action) => ArgumentNullException.ThrowIfNull(action);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
