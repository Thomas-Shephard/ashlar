using Ashlar.Auditing;
using Ashlar.Identity.Abstractions.Repositories;
using Ashlar.Identity.Abstractions.Services;
using Ashlar.Identity.Models.AccountSecurity;
using Ashlar.Identity.Models.Authentication;
using Ashlar.Identity.Models.Sessions;
using Ashlar.Identity.Models.Tenants;
using System.Diagnostics.CodeAnalysis;

namespace Ashlar.Testing;

/// <summary>Creates a valid account-security actor and its test dependencies.</summary>
public sealed class AccountSecurityActorTestContext
{
    /// <summary>Initializes a test actor with a fresh proof and active session.</summary>
    public AccountSecurityActorTestContext(DateTimeOffset now, string proofPurpose, bool authorized = true)
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        Actor = new AccountSecurityActorContext(userId, TenantContext.Global, sessionId,
            FreshMfaVerificationProofFactory.Create(userId, null, sessionId, now, now.AddMinutes(5), proofPurpose),
            new AuditContext(userId));
        Sessions.Session = new AuthenticationSession
        {
            Id = sessionId,
            UserId = userId,
            TokenHash = "hash",
            CreatedAt = now,
            ExpiresAt = now.AddHours(1)
        };
        Authorizer.Authorized = authorized;
    }

    /// <summary>Gets or sets the actor supplied to the operation under test.</summary>
    public AccountSecurityActorContext Actor { get; set; }
    /// <summary>Gets the actor's session repository.</summary>
    public StubAuthenticationSessionRepository Sessions { get; } = new();
    /// <summary>Gets the configurable host authorizer.</summary>
    public StubAccountSecurityOperationAuthorizer Authorizer { get; } = new();
    /// <summary>Gets the durable audit recorder.</summary>
    public RecordingPersistentSecurityEventSink AuditSink { get; } = new();
}

/// <summary>Configurable account-security operation authorizer for tests.</summary>
public sealed class StubAccountSecurityOperationAuthorizer : IAccountSecurityOperationAuthorizer
{
    /// <summary>Gets or sets whether authorization succeeds.</summary>
    public bool Authorized { get; set; }
    /// <summary>Gets the most recent authorization context.</summary>
    public AccountSecurityAuthorizationContext? LastContext { get; private set; }

    /// <inheritdoc />
    public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default)
    {
        LastContext = context;
        return ValueTask.FromResult(Authorized);
    }
}

/// <summary>Minimal authentication-session repository for account-security tests.</summary>
[ExcludeFromCodeCoverage]
public sealed class StubAuthenticationSessionRepository : IAuthenticationSessionRepository
{
    /// <summary>Gets or sets the primary session returned by the repository.</summary>
    public AuthenticationSession? Session { get; set; }
    /// <summary>Gets additional sessions returned by identifier.</summary>
    public List<AuthenticationSession> AdditionalSessions { get; } = [];
    /// <inheritdoc />
    public Task<AuthenticationSession?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Session?.Id == sessionId ? Session : AdditionalSessions.SingleOrDefault(session => session.Id == sessionId));
    /// <inheritdoc />
    public Task CreateSessionAsync(AuthenticationSession session, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<AuthenticationSession?> GetSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<bool> UpdateSessionLastSeenAsync(Guid sessionId, DateTimeOffset lastSeenAt, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<AuthenticationSession?> MarkStepUpVerifiedAsync(Guid sessionId, Guid userId, DateTimeOffset verifiedAt, AuthenticationProviderKey verifiedProvider, string verifiedFactor, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<int> RevokeSessionsForUserAsync(Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<IReadOnlyList<AuthenticationSession>> ListSessionsForUserAsync(Guid userId, bool activeOnly, DateTimeOffset now, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<bool> RevokeSessionByIdAsync(Guid sessionId, Guid userId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public Task<int> RevokeOtherSessionsForUserAsync(Guid userId, Guid excludedSessionId, DateTimeOffset revokedAt, string? reason, TenantContext? tenant, bool includeAllTenants, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}

/// <summary>Records durable security events in memory for tests.</summary>
public sealed class RecordingPersistentSecurityEventSink : IPersistentSecurityEventSink
{
    /// <summary>Gets the recorded security events.</summary>
    public List<AshlarSecurityEvent> Events { get; } = [];
    /// <inheritdoc />
    public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
    {
        Events.Add(securityEvent);
        return Task.CompletedTask;
    }
}
