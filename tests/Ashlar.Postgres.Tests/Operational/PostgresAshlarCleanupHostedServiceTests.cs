using System.Diagnostics.CodeAnalysis;
using Ashlar.Operational;
using Ashlar.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.Operational;

internal sealed class PostgresAshlarCleanupHostedServiceTests
{
    [Test]
    public async Task HostedServiceRunsCleanupAndWaitsForInterval()
    {
        var cleanup = new RecordingCleanupService();
        var timeProvider = new FakeTimeProvider();
        await using var provider = BuildProvider(cleanup);
        var service = new PostgresAshlarCleanupHostedService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            timeProvider,
            Options.Create(new AshlarCleanupOptions { CleanupInterval = TimeSpan.FromMinutes(5) }),
            null,
            RunCleanupAsync);

        await service.StartAsync(CancellationToken.None);
        await WaitForCountAsync(cleanup, 1);
        timeProvider.Advance(TimeSpan.FromMinutes(4));
        await Task.Delay(20);
        Assert.That(cleanup.Count, Is.EqualTo(1));

        timeProvider.Advance(TimeSpan.FromMinutes(1));
        await WaitForCountAsync(cleanup, 2);
        await service.StopAsync(CancellationToken.None);
    }

    [Test]
    public async Task HostedServiceSuppressesCleanupFailureAndContinues()
    {
        var cleanup = new RecordingCleanupService { ThrowOnFirstCall = true };
        var timeProvider = new FakeTimeProvider();
        var logger = new RecordingLogger<PostgresAshlarCleanupHostedService>();
        await using var provider = BuildProvider(cleanup);
        var service = new PostgresAshlarCleanupHostedService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            timeProvider,
            Options.Create(new AshlarCleanupOptions { CleanupInterval = TimeSpan.FromSeconds(1) }),
            logger,
            RunCleanupAsync);

        await service.StartAsync(CancellationToken.None);
        await WaitForCountAsync(cleanup, 1);
        timeProvider.Advance(TimeSpan.FromSeconds(1));
        await WaitForCountAsync(cleanup, 2);
        await service.StopAsync(CancellationToken.None);

        Assert.That(logger.Entries, Has.Some.Matches<LogEntry>(entry =>
            entry.Level == LogLevel.Error
            && entry.Message.Contains("cleanup hosted service run failed", StringComparison.Ordinal)));
    }

    [Test]
    public async Task HostedServiceStopsWhenCancelledDuringCleanup()
    {
        var cleanup = new RecordingCleanupService { WaitForCancellation = true };
        var timeProvider = new FakeTimeProvider();
        await using var provider = BuildProvider(cleanup);
        var service = new PostgresAshlarCleanupHostedService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            timeProvider,
            Options.Create(new AshlarCleanupOptions { CleanupInterval = TimeSpan.FromSeconds(1) }),
            null,
            RunCleanupAsync);

        await service.StartAsync(CancellationToken.None);
        await WaitForCountAsync(cleanup, 1);
        await service.StopAsync(CancellationToken.None);

        Assert.That(cleanup.Count, Is.EqualTo(1));
    }

    [Test]
    public async Task HostedServiceRejectsInvalidOptions()
    {
        var cleanup = new RecordingCleanupService();
        var timeProvider = new FakeTimeProvider();
        await using var provider = BuildProvider(cleanup);
        var service = new PostgresAshlarCleanupHostedService(
            provider.GetRequiredService<IServiceScopeFactory>(),
            timeProvider,
            Options.Create(new AshlarCleanupOptions { CleanupInterval = TimeSpan.Zero }),
            null,
            RunCleanupAsync);

        await service.StartAsync(CancellationToken.None);
        var executeTask = service.ExecuteTask;

        Assert.That(executeTask, Is.Not.Null);
        Assert.ThrowsAsync<InvalidOperationException>(async () => await executeTask);
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorRejectsNullArguments()
    {
        var cleanup = new RecordingCleanupService();
        using var provider = BuildProvider(cleanup);
        var scopeFactory = provider.GetRequiredService<IServiceScopeFactory>();
        var timeProvider = new FakeTimeProvider();
        var options = Options.Create(new AshlarCleanupOptions());

        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupHostedService(null!, timeProvider, options));
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupHostedService(scopeFactory, null!, options));
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAshlarCleanupHostedService(scopeFactory, timeProvider, null!));
    }

    private static ServiceProvider BuildProvider(RecordingCleanupService cleanup)
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => cleanup);
        return services.BuildServiceProvider();
    }

    private static async Task WaitForCountAsync(RecordingCleanupService cleanup, int expected)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            if (cleanup.Count >= expected)
            {
                return;
            }

            await Task.Delay(10);
        }

        Assert.Fail($"Expected cleanup count to reach {expected}, but it was {cleanup.Count}.");
    }

    private static Task<AshlarCleanupResult> RunCleanupAsync(
        IServiceProvider services,
        CancellationToken cancellationToken) =>
        services.GetRequiredService<RecordingCleanupService>().CleanupAsync(cancellationToken);

    private sealed class RecordingCleanupService
    {
        public int Count { get; private set; }
        public bool ThrowOnFirstCall { get; init; }
        public bool WaitForCancellation { get; init; }

        public async Task<AshlarCleanupResult> CleanupAsync(CancellationToken cancellationToken = default)
        {
            Count++;
            if (WaitForCancellation)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            if (ThrowOnFirstCall && Count == 1)
            {
                throw new InvalidOperationException("cleanup failed");
            }

            return AshlarCleanupResult.Empty;
        }
    }
}
