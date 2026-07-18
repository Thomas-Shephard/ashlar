namespace Ashlar.Passkeys.Tests;

internal sealed record TestUser(Guid Id, string DisplayEmail, UserAccountState AccountState = UserAccountState.Active, Guid? TenantId = null) : ITenantUser
{
    public string? Name => null;
    public DateTimeOffset? EmailVerifiedAt => null;
}

internal sealed class RecordingTransactionProvider : IAshlarTransactionProvider
{
    public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IAshlarTransaction>(new RecordingTransaction());

    private sealed class RecordingTransaction : IAshlarTransaction
    {
        public Task CommitAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task RollbackAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void OnCommitted(Func<CancellationToken, Task> callback) { }
    }
}
