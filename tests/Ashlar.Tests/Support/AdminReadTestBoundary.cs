using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Support;

internal sealed class AdminReadTestBoundary(DateTimeOffset now, bool authorized = true,
    string proofPurpose = AccountSecurityActorContext.AdministrationReadProofPurpose,
    bool sessionRevoked = false)
{
    private readonly Mock<IAuthenticationSessionRepository> _sessions = new();
    private readonly List<AccountSecurityAuthorizationContext> _authorizationContexts = [];

    public AccountSecurityActorContext Actor { get; } = CreateActor(now, proofPurpose);
    public IAccountSecurityOperationAuthorizer Authorizer => new FixedAuthorizer(authorized, _authorizationContexts);
    public IReadOnlyList<AccountSecurityAuthorizationContext> AuthorizationContexts => _authorizationContexts;
    public RecordingSink Sink { get; } = new();
    public TimeProvider TimeProvider { get; } = new FakeTimeProvider(now);

    public IAuthenticationSessionRepository Sessions
    {
        get
        {
            _sessions.Setup(repository => repository.GetSessionAsync(Actor.CurrentSessionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new AuthenticationSession
                {
                    Id = Actor.CurrentSessionId,
                    UserId = Actor.ActorUserId,
                    TenantId = Actor.ActorTenant.TenantId,
                    TokenHash = "test",
                    CreatedAt = now,
                    ExpiresAt = now.AddYears(1),
                    RevokedAt = sessionRevoked ? now : null
                });
            return _sessions.Object;
        }
    }

    private static AccountSecurityActorContext CreateActor(DateTimeOffset now, string proofPurpose)
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        return new AccountSecurityActorContext(userId, TenantContext.Global, sessionId,
            new FreshMfaVerificationProof(userId, null, sessionId, now, now.AddMinutes(5), proofPurpose),
            new AuditContext(userId));
    }

    private sealed class FixedAuthorizer(bool authorized, List<AccountSecurityAuthorizationContext> contexts) : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default)
        {
            contexts.Add(context);
            return ValueTask.FromResult(authorized);
        }
    }

    internal sealed class RecordingSink : IPersistentSecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }
}
