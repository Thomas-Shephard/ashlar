using Ashlar.Auditing;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Support;

internal sealed class AdminReadTestBoundary(DateTimeOffset now, bool authorized = true)
{
    private readonly Mock<IAuthenticationSessionRepository> _sessions = new();

    public AccountSecurityActorContext Actor { get; } = CreateActor(now);
    public IAccountSecurityOperationAuthorizer Authorizer { get; } = new FixedAuthorizer(authorized);
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
                    ExpiresAt = now.AddYears(1)
                });
            return _sessions.Object;
        }
    }

    private static AccountSecurityActorContext CreateActor(DateTimeOffset now)
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        return new AccountSecurityActorContext(userId, TenantContext.Global, sessionId,
            new FreshMfaVerificationProof(userId, null, sessionId, now, now.AddMinutes(5), AccountSecurityActorContext.AdministrationReadProofPurpose),
            new AuditContext(userId));
    }

    private sealed class FixedAuthorizer(bool authorized) : IAccountSecurityOperationAuthorizer
    {
        public ValueTask<bool> AuthorizeAsync(AccountSecurityAuthorizationContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(authorized);
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
