using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class AshlarEmailOutboxDiagnosticsRunnerTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 20, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CheckAsyncReturnsHealthyResultWhenOutboxCanBeQueried()
    {
        var runner = new AshlarEmailOutboxDiagnosticsRunner("TestProvider");
        var oldestPendingAt = CheckedAt.AddMinutes(-10);
        var oldestFailedAt = CheckedAt.AddHours(-1);

        var result = await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            _ => new ValueTask<TestConnection>(new TestConnection()),
            (_, _) => Task.FromResult(true),
            (_, now, _) => Task.FromResult(new EmailOutboxDiagnosticSnapshot
            {
                PendingCount = 1,
                ScheduledCount = 2,
                LockedCount = 3,
                ExpiredLockCount = 4,
                FailedCount = 5,
                OldestPendingAt = oldestPendingAt,
                OldestFailedAt = oldestFailedAt
            }),
            6,
            TimeSpan.FromSeconds(7),
            8,
            _ => Assert.Fail("No exception should be logged."));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.PendingCount, Is.EqualTo(1));
            Assert.That(result.ScheduledCount, Is.EqualTo(2));
            Assert.That(result.LockedCount, Is.EqualTo(3));
            Assert.That(result.ExpiredLockCount, Is.EqualTo(4));
            Assert.That(result.FailedCount, Is.EqualTo(5));
            Assert.That(result.OldestPendingAt, Is.EqualTo(oldestPendingAt));
            Assert.That(result.OldestFailedAt, Is.EqualTo(oldestFailedAt));
            Assert.That(result.MaxAttempts, Is.EqualTo(6));
            Assert.That(result.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(7)));
            Assert.That(result.BatchSize, Is.EqualTo(8));
        }
    }

    [Test]
    public async Task CheckAsyncReturnsNotSupportedWhenTableIsMissing()
    {
        var runner = new AshlarEmailOutboxDiagnosticsRunner("TestProvider");

        var result = await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            _ => new ValueTask<TestConnection>(new TestConnection()),
            (_, _) => Task.FromResult(false),
            (_, _, _) => throw new InvalidOperationException("Should not query missing table."),
            6,
            TimeSpan.FromSeconds(7),
            8,
            _ => Assert.Fail("No exception should be logged."));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.Reason, Is.EqualTo("Email outbox table has not been initialized."));
            Assert.That(result.PendingCount, Is.Null);
            Assert.That(result.MaxAttempts, Is.EqualTo(6));
            Assert.That(result.PollingInterval, Is.EqualTo(TimeSpan.FromSeconds(7)));
            Assert.That(result.BatchSize, Is.EqualTo(8));
        }
    }

    [Test]
    public async Task CheckAsyncReturnsUnknownAndLogsUnexpectedFailures()
    {
        var runner = new AshlarEmailOutboxDiagnosticsRunner("TestProvider");
        Exception? loggedException = null;
        var exception = new InvalidOperationException("Sensitive failure details.");

        var result = await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            _ => new ValueTask<TestConnection>(new TestConnection()),
            (_, _) => throw exception,
            (_, _, _) => Task.FromResult(new EmailOutboxDiagnosticSnapshot()),
            6,
            TimeSpan.FromSeconds(7),
            8,
            ex => loggedException = ex);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Email outbox diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain("Sensitive"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.PendingCount, Is.Null);
            Assert.That(loggedException, Is.SameAs(exception));
        }
    }

    [Test]
    public void CheckAsyncPropagatesCancellation()
    {
        var runner = new AshlarEmailOutboxDiagnosticsRunner("TestProvider");
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            token =>
            {
                token.ThrowIfCancellationRequested();
                return new ValueTask<TestConnection>(new TestConnection());
            },
            (_, _) => Task.FromResult(true),
            (_, _, _) => Task.FromResult(new EmailOutboxDiagnosticSnapshot()),
            6,
            TimeSpan.FromSeconds(7),
            8,
            _ => Assert.Fail("No exception should be logged."),
            cancellationTokenSource.Token));
    }

    [Test]
    public void CheckAsyncRejectsNullArguments()
    {
        var runner = new AshlarEmailOutboxDiagnosticsRunner("TestProvider");
        var timeProvider = new FakeTimeProvider(CheckedAt);
        Func<CancellationToken, ValueTask<TestConnection>> openConnection = _ => new ValueTask<TestConnection>(new TestConnection());
        Func<TestConnection, CancellationToken, Task<bool>> tableExists = (_, _) => Task.FromResult(true);
        Func<TestConnection, DateTimeOffset, CancellationToken, Task<EmailOutboxDiagnosticSnapshot>> querySnapshot =
            (_, _, _) => Task.FromResult(new EmailOutboxDiagnosticSnapshot());
        Action<Exception> logException = _ => { };

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync<TestConnection>(null!, openConnection, tableExists, querySnapshot, 1, TimeSpan.FromSeconds(1), 1, logException));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, null!, tableExists, querySnapshot, 1, TimeSpan.FromSeconds(1), 1, logException));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, openConnection, null!, querySnapshot, 1, TimeSpan.FromSeconds(1), 1, logException));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, openConnection, tableExists, null!, 1, TimeSpan.FromSeconds(1), 1, logException));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, openConnection, tableExists, querySnapshot, 1, TimeSpan.FromSeconds(1), 1, null!));
        }
    }

    private sealed class TestConnection : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }
}
