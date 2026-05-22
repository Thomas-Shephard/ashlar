using System.Globalization;
using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.RateLimiting;

internal sealed class SqliteAuthenticationRateLimiterDiagnosticsTests : SqliteTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 21, 10, 0, 0, TimeSpan.Zero);
    private ServiceProvider _provider = null!;
    private FakeTimeProvider _timeProvider = null!;

    [SetUp]
    public async Task SetUpAsync()
    {
        _timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddAshlarSqlite(GetConnectionString());
        services.AddSingleton<TimeProvider>(_timeProvider);
        _provider = services.BuildServiceProvider();
        await _provider.InitializeAshlarSqliteSchemaAsync();
    }

    [TearDown]
    public async Task TearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [Test]
    public async Task AddAshlarSqliteRegistersDiagnostics()
    {
        await using var scope = _provider.CreateAsyncScope();

        var diagnostics = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>();

        Assert.That(diagnostics, Is.TypeOf<SqliteAuthenticationRateLimiterDiagnostics>());
    }

    [Test]
    public async Task CheckAsyncEmptyTableReturnsHealthyZeroCounts()
    {
        var result = await CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("Sqlite"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.Distributed, Is.False);
            Assert.That(result.Persistent, Is.True);
            Assert.That(result.ActiveKeyCount, Is.Zero);
            Assert.That(result.ExpiredRowCount, Is.Zero);
            Assert.That(result.BlockedKeyCount, Is.Zero);
            Assert.That(result.CleanupConfigured, Is.Null);
            Assert.That(result.CleanupInterval, Is.Null);
            Assert.That(result.MaxCleanupRows, Is.Null);
        }
    }

    [Test]
    public async Task CheckAsyncCountsActiveExpiredAndBlockedRows()
    {
        await using var connection = await OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, blocked_until, expires_at)
            VALUES
                ('login', 'active', 1, $now, NULL, $future),
                ('login', 'expired', 1, $past, NULL, $past),
                ('login', 'blocked', 2, $now, $future, $future);
            """;
        command.AddParameter("$now", Format(CheckedAt));
        command.AddParameter("$past", Format(CheckedAt.AddMinutes(-1)));
        command.AddParameter("$future", Format(CheckedAt.AddMinutes(5)));
        await command.ExecuteNonQueryAsync();

        var result = await CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ActiveKeyCount, Is.EqualTo(2));
            Assert.That(result.ExpiredRowCount, Is.EqualTo(1));
            Assert.That(result.BlockedKeyCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = new SqliteTransactionManager(new SqliteConnectionFactory(GetConnectionString()));

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteAuthenticationRateLimiterDiagnostics(null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new SqliteAuthenticationRateLimiterDiagnostics(connectionProvider, null!));
        }
    }

    [Test]
    public async Task CheckAsyncReturnsUnknownAndLogsWhenProviderQueryFails()
    {
        var exception = new InvalidOperationException("Sensitive failure details.");
        var connectionProvider = new SqliteTransactionManager(_ => throw exception);
        var diagnostics = new SqliteAuthenticationRateLimiterDiagnostics(
            connectionProvider,
            _timeProvider,
            NullLogger<SqliteAuthenticationRateLimiterDiagnostics>.Instance);

        var result = await diagnostics.CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Unknown));
            Assert.That(result.Reason, Is.EqualTo("Authentication rate limiter diagnostics could not query provider state."));
            Assert.That(result.Reason, Does.Not.Contain("Sensitive"));
        }
    }

    private async Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync()
    {
        await using var scope = _provider.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>().CheckAsync();
    }

    private static string Format(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }
}
