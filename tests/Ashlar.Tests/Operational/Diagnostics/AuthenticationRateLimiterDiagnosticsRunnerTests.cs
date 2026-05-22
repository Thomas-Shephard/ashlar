using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Tests.Operational.Diagnostics;

internal sealed class AuthenticationRateLimiterDiagnosticsRunnerTests
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 21, 12, 0, 0, TimeSpan.Zero);
    private static readonly AuthenticationRateLimiterDiagnosticOptions Options = new(
        true,
        true,
        true,
        true,
        TimeSpan.FromMinutes(5),
        100);

    [Test]
    public async Task CheckAsyncReturnsHealthyResultWhenStateCanBeQueried()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");

        var result = await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(
                _ => new ValueTask<TestConnection>(new TestConnection()),
                (_, _) => Task.FromResult(true),
                (_, _, _) => Task.FromResult(new AuthenticationRateLimiterDiagnosticSnapshot
                {
                    ActiveKeyCount = 1,
                    ExpiredRowCount = 2,
                    BlockedKeyCount = 3
                }),
                _ => Assert.Fail("No exception should be logged.")),
            Options);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("TestProvider"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.ActiveKeyCount, Is.EqualTo(1));
            Assert.That(result.ExpiredRowCount, Is.EqualTo(2));
            Assert.That(result.BlockedKeyCount, Is.EqualTo(3));
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(5)));
            Assert.That(result.MaxCleanupRows, Is.EqualTo(100));
        }
    }

    [Test]
    public async Task CheckAsyncReturnsNotSupportedWhenTableIsMissing()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");

        var result = await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(
                _ => new ValueTask<TestConnection>(new TestConnection()),
                (_, _) => Task.FromResult(false),
                (_, _, _) => throw new InvalidOperationException("Should not query missing table."),
                _ => Assert.Fail("No exception should be logged.")),
            Options);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.Reason, Is.EqualTo("Authentication rate limiter table has not been initialized."));
            Assert.That(result.ActiveKeyCount, Is.Null);
            Assert.That(result.ExpiredRowCount, Is.Null);
            Assert.That(result.BlockedKeyCount, Is.Null);
        }
    }

    [Test]
    public async Task CheckAsyncReturnsUnknownAndLogsUnexpectedFailures()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");
        Exception? loggedException = null;
        var exception = new InvalidOperationException("Sensitive failure details.");

        var result = await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(
                _ => new ValueTask<TestConnection>(new TestConnection()),
                (_, _) => throw exception,
                (_, _, _) => Task.FromResult(new AuthenticationRateLimiterDiagnosticSnapshot()),
                ex => loggedException = ex),
            Options);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Authentication rate limiter diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain("Sensitive"));
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.ActiveKeyCount, Is.Null);
            Assert.That(loggedException, Is.SameAs(exception));
        }
    }

    [Test]
    public void CheckAsyncPropagatesCancellation()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () => await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(
                token =>
                {
                    token.ThrowIfCancellationRequested();
                    return new ValueTask<TestConnection>(new TestConnection());
                },
                (_, _) => Task.FromResult(true),
                (_, _, _) => Task.FromResult(new AuthenticationRateLimiterDiagnosticSnapshot()),
                _ => Assert.Fail("No exception should be logged.")),
            Options,
            cancellationTokenSource.Token));
    }

    [Test]
    public void CheckAsyncPropagatesCancellationAfterConnectionOpens()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");

        Assert.ThrowsAsync<OperationCanceledException>(async () => await runner.CheckAsync(
            new FakeTimeProvider(CheckedAt),
            new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(
                _ => new ValueTask<TestConnection>(new TestConnection()),
                (_, _) => throw new OperationCanceledException(),
                (_, _, _) => Task.FromResult(new AuthenticationRateLimiterDiagnosticSnapshot()),
                _ => Assert.Fail("No exception should be logged.")),
            Options));
    }

    [Test]
    public void CheckAsyncRejectsNullArguments()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");
        var timeProvider = new FakeTimeProvider(CheckedAt);
        Func<CancellationToken, ValueTask<TestConnection>> openConnection = _ => new ValueTask<TestConnection>(new TestConnection());
        Func<TestConnection, CancellationToken, Task<bool>> tableExists = (_, _) => Task.FromResult(true);
        Func<TestConnection, DateTimeOffset, CancellationToken, Task<AuthenticationRateLimiterDiagnosticSnapshot>> querySnapshot =
            (_, _, _) => Task.FromResult(new AuthenticationRateLimiterDiagnosticSnapshot());
        Action<Exception> logException = _ => { };
        var context = new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(openConnection, tableExists, querySnapshot, logException);

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync<TestConnection>(null!, context, Options));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync<TestConnection>(timeProvider, null!, Options));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, context, null!));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(null!, tableExists, querySnapshot, logException), Options));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(openConnection, null!, querySnapshot, logException), Options));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(openConnection, tableExists, null!, logException), Options));
            Assert.ThrowsAsync<ArgumentNullException>(async () => await runner.CheckAsync(timeProvider, new AuthenticationRateLimiterDiagnosticsContext<TestConnection>(openConnection, tableExists, querySnapshot, null!), Options));
        }
    }

    [Test]
    public void HealthyRejectsNullArguments()
    {
        var runner = new AuthenticationRateLimiterDiagnosticsRunner("TestProvider");
        var timeProvider = new FakeTimeProvider(CheckedAt);
        var snapshot = new AuthenticationRateLimiterDiagnosticSnapshot();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => runner.Healthy(null!, Options, snapshot));
            Assert.Throws<ArgumentNullException>(() => runner.Healthy(timeProvider, null!, snapshot));
            Assert.Throws<ArgumentNullException>(() => runner.Healthy(timeProvider, Options, null!));
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
