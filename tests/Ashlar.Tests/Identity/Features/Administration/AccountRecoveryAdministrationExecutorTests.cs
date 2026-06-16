using Ashlar.Auditing;

namespace Ashlar.Tests.Identity.Features.Administration;

internal sealed class AccountRecoveryAdministrationExecutorTests
{
    [Test]
    public void ConstructorRejectsNullDependency()
    {
        Assert.Throws<ArgumentNullException>(() => new AccountRecoveryAdministrationExecutor(null!));
    }

    [Test]
    public void MethodsRejectNullRequests()
    {
        var executor = CreateExecutor();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => executor.ResetMfaAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => executor.RevokeSessionsAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => executor.RevokeProviderCredentialsAsync(null!));
        }
    }

    [Test]
    public void RequestsRequireUserScopeAuditAndProvider()
    {
        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentException>(() => new AccountRecoveryResetMfaRequest(Guid.Empty, CreateAudit(), TenantContext.Global));
            Assert.Throws<ArgumentException>(() => new AccountRecoveryRevokeSessionsRequest(Guid.NewGuid(), CreateAudit()));
            Assert.Throws<ArgumentException>(() => new AccountRecoveryRevokeSessionsRequest(Guid.NewGuid(), CreateAudit(), TenantContext.Global, IncludeAllTenants: true));
            Assert.Throws<ArgumentNullException>(() => new AccountRecoveryResetMfaRequest(Guid.NewGuid(), null!, TenantContext.Global));
            Assert.Throws<ArgumentException>(() => new AccountRecoveryRevokeProviderCredentialsRequest(Guid.NewGuid(), default, CreateAudit(), TenantContext.Global));
            Assert.Throws<ArgumentException>(() => new AccountRecoveryRevokeProviderCredentialsRequest(Guid.NewGuid(), new AuthenticationProviderKey(ProviderType.StorageFallbackValue, "unknown"), CreateAudit(), TenantContext.Global));
            Assert.Throws<ArgumentException>(() => new AccountRecoveryRevokeProviderCredentialsRequest(Guid.NewGuid(), new AuthenticationProviderKey(ProviderType.Internal, "password-reset"), CreateAudit(), TenantContext.Global));
        }
    }

    [Test]
    public async Task ResetMfaAsyncDelegatesToAccountSecurityService()
    {
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var audit = CreateAudit();
        var security = new RecordingAccountSecurityService(Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 2, RememberedMfaDevicesRevoked: 1)));
        var executor = CreateExecutor(security);
        using var cancellation = new CancellationTokenSource();

        var result = await executor.ResetMfaAsync(new AccountRecoveryResetMfaRequest(userId, audit, tenant, "lost-device"), cancellation.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(2));
            Assert.That(result.Value?.RememberedMfaDevicesRevoked, Is.EqualTo(1));
            Assert.That(security.LastOperation, Is.EqualTo("ResetMfa"));
            Assert.That(security.LastUserId, Is.EqualTo(userId));
            Assert.That(security.LastRequest?.Audit, Is.SameAs(audit));
            Assert.That(security.LastRequest?.Tenant, Is.EqualTo(tenant));
            Assert.That(security.LastRequest?.Reason, Is.EqualTo("lost-device"));
            Assert.That(security.LastCancellationToken, Is.EqualTo(cancellation.Token));
        }
    }

    [Test]
    public async Task RevokeSessionsAsyncDelegatesToAccountSecurityServiceAndPreservesNoOpCounts()
    {
        var userId = Guid.NewGuid();
        var security = new RecordingAccountSecurityService(Result.Success(new AccountSecurityOperationResult(userId)));
        var executor = CreateExecutor(security);
        using var cancellation = new CancellationTokenSource();

        var result = await executor.RevokeSessionsAsync(new AccountRecoveryRevokeSessionsRequest(userId, CreateAudit(), IncludeAllTenants: true), cancellation.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.SessionsRevoked, Is.Zero);
            Assert.That(security.LastOperation, Is.EqualTo("RevokeSessions"));
            Assert.That(security.LastRequest?.Tenant, Is.Null);
            Assert.That(security.LastRequest?.IncludeAllTenants, Is.True);
            Assert.That(security.LastCancellationToken, Is.EqualTo(cancellation.Token));
        }
    }

    [Test]
    public async Task RevokeProviderCredentialsAsyncDelegatesToAccountSecurityService()
    {
        var userId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var security = new RecordingAccountSecurityService(Result.Success(new AccountSecurityOperationResult(userId, CredentialsRevoked: 3)));
        var executor = CreateExecutor(security);
        using var cancellation = new CancellationTokenSource();

        var result = await executor.RevokeProviderCredentialsAsync(
            new AccountRecoveryRevokeProviderCredentialsRequest(userId, provider, CreateAudit(), TenantContext.Global, "provider-compromise"),
            cancellation.Token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.CredentialsRevoked, Is.EqualTo(3));
            Assert.That(security.LastOperation, Is.EqualTo("RevokeCredentials"));
            Assert.That(security.LastProvider, Is.EqualTo(provider));
            Assert.That(security.LastRequest?.Tenant, Is.EqualTo(TenantContext.Global));
            Assert.That(security.LastRequest?.Reason, Is.EqualTo("provider-compromise"));
            Assert.That(security.LastCancellationToken, Is.EqualTo(cancellation.Token));
        }
    }

    [TestCase("missing-user")]
    [TestCase("tenant-mismatch")]
    [TestCase("guard-failure")]
    public async Task ExecutorPropagatesAccountSecurityFailures(string failureCode)
    {
        var security = new RecordingAccountSecurityService(Result.Failure<AccountSecurityOperationResult>(new AshlarFailureCode(failureCode), "blocked"));
        var executor = CreateExecutor(security);

        var result = await executor.ResetMfaAsync(new AccountRecoveryResetMfaRequest(Guid.NewGuid(), CreateAudit(), TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(new AshlarFailureCode(failureCode)));
            Assert.That(result.FailureMessage, Is.EqualTo("blocked"));
        }
    }

    private static AccountRecoveryAdministrationExecutor CreateExecutor(RecordingAccountSecurityService? accountSecurityService = null)
    {
        return new AccountRecoveryAdministrationExecutor(accountSecurityService ?? new RecordingAccountSecurityService(Result.Success(new AccountSecurityOperationResult(Guid.NewGuid()))));
    }

    private static AuditContext CreateAudit() => new(CorrelationId: "corr");

    private sealed class RecordingAccountSecurityService(Result<AccountSecurityOperationResult> result) : IAccountSecurityService
    {
        public string? LastOperation { get; private set; }
        public Guid LastUserId { get; private set; }
        public AuthenticationProviderKey? LastProvider { get; private set; }
        public AccountSecurityOperationRequest? LastRequest { get; private set; }
        public CancellationToken LastCancellationToken { get; private set; }

        public Task<Result<AccountSecurityOperationResult>> SetUserAccountStateAsync(Guid userId, SetUserAccountStateRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            LastOperation = "RevokeSessions";
            LastUserId = userId;
            LastRequest = request;
            LastCancellationToken = cancellationToken;
            return Task.FromResult(result);
        }

        public Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            LastOperation = "RevokeCredentials";
            LastUserId = userId;
            LastProvider = provider;
            LastRequest = request;
            LastCancellationToken = cancellationToken;
            return Task.FromResult(result);
        }

        public Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
        {
            LastOperation = "ResetMfa";
            LastUserId = userId;
            LastRequest = request;
            LastCancellationToken = cancellationToken;
            return Task.FromResult(result);
        }

        public Task<Result<AccountSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, AccountSecurityPostureRequest? request = null, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
