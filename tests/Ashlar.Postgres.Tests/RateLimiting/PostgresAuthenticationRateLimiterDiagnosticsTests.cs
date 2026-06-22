using Ashlar.Operational.Diagnostics;
using Dapper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Postgres.Tests.RateLimiting;

internal sealed class PostgresAuthenticationRateLimiterDiagnosticsTests : PostgresTestBase
{
    private static readonly DateTimeOffset CheckedAt = new(2026, 5, 21, 10, 0, 0, TimeSpan.Zero);
    private ServiceProvider _provider = null!;
    private FakeTimeProvider _timeProvider = null!;

    public override async Task OneTimeSetUp()
    {
        await base.OneTimeSetUp();

        _timeProvider = new FakeTimeProvider(CheckedAt);
        var services = new ServiceCollection();
        services.AddAshlarPostgres(GetConnectionString());
        services.AddAshlarPostgresRateLimiting(options =>
        {
            options.CleanupInterval = TimeSpan.FromMinutes(7);
            options.MaxCleanupRows = 123;
        });
        services.AddSingleton<TimeProvider>(_timeProvider);
        _provider = services.BuildServiceProvider();

        await _provider.InitializeAshlarPostgresSchemaAsync();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        await _provider.DisposeAsync();
    }

    [SetUp]
    public async Task SetUpAsync()
    {
        await _provider.InitializeAshlarPostgresSchemaAsync();
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("TRUNCATE ashlar_rate_limits");
    }

    [Test]
    public async Task AddAshlarPostgresRateLimitingRegistersDiagnostics()
    {
        await using var scope = _provider.CreateAsyncScope();

        var diagnostics = scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>();

        Assert.That(diagnostics, Is.TypeOf<PostgresAuthenticationRateLimiterDiagnostics>());
    }

    [Test]
    public async Task CheckAsyncEmptyTableReturnsHealthyZeroCountsAndOptions()
    {
        var result = await CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.Healthy));
            Assert.That(result.ProviderName, Is.EqualTo("PostgreSQL"));
            Assert.That(result.Reason, Is.Null);
            Assert.That(result.CheckedAt, Is.EqualTo(CheckedAt));
            Assert.That(result.Configured, Is.True);
            Assert.That(result.Distributed, Is.True);
            Assert.That(result.Persistent, Is.True);
            Assert.That(result.ActiveKeyCount, Is.Zero);
            Assert.That(result.ExpiredRowCount, Is.Zero);
            Assert.That(result.BlockedKeyCount, Is.Zero);
            Assert.That(result.CleanupConfigured, Is.True);
            Assert.That(result.CleanupInterval, Is.EqualTo(TimeSpan.FromMinutes(7)));
            Assert.That(result.MaxCleanupRows, Is.EqualTo(123));
        }
    }

    [Test]
    public async Task CheckAsyncCountsActiveExpiredAndBlockedRows()
    {
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync(
            """
            INSERT INTO ashlar_rate_limits (purpose, rate_limit_key, count, window_start, blocked_until, expires_at)
            VALUES
                ('login', 'active', 1, @Now, NULL, @Future),
                ('login', 'expired', 1, @Past, NULL, @Past),
                ('login', 'blocked', 2, @Now, @Future, @Future);
            """,
            new
            {
                Now = CheckedAt,
                Past = CheckedAt.AddMinutes(-1),
                Future = CheckedAt.AddMinutes(5)
            });

        var result = await CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.ActiveKeyCount, Is.EqualTo(2));
            Assert.That(result.ExpiredRowCount, Is.EqualTo(1));
            Assert.That(result.BlockedKeyCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CheckAsyncMissingTableReturnsSafeNonThrowingResult()
    {
        var builder = new Npgsql.NpgsqlConnectionStringBuilder(GetConnectionString())
        {
            SearchPath = "missing_rate_limiter_diagnostics"
        };
        await using var connection = await GetDataSource().OpenConnectionAsync();
        await connection.ExecuteAsync("CREATE SCHEMA IF NOT EXISTS missing_rate_limiter_diagnostics");

        var services = new ServiceCollection();
        services.AddAshlarPostgres(builder.ConnectionString);
        services.AddAshlarPostgresRateLimiting();
        services.AddSingleton<TimeProvider>(_timeProvider);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        var result = await scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiterDiagnostics>().CheckAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Status, Is.EqualTo(AshlarDiagnosticStatus.NotSupported));
            Assert.That(result.Reason, Is.Not.Null);
            Assert.That(result.ActiveKeyCount, Is.Null);
            Assert.That(result.ExpiredRowCount, Is.Null);
            Assert.That(result.BlockedKeyCount, Is.Null);
        }
    }

    [Test]
    public void ConstructorRejectsNullArguments()
    {
        var connectionProvider = new PostgresTransactionManager(GetDataSource());
        var options = Options.Create(new PostgresAuthenticationRateLimiterOptions());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationRateLimiterDiagnostics(null!, options, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationRateLimiterDiagnostics(connectionProvider, null!, _timeProvider));
            Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationRateLimiterDiagnostics(connectionProvider, options, null!));
        }
    }

    [Test]
    public async Task CheckAsyncReturnsUnknownAndLogsWhenProviderQueryFails()
    {
        var exception = new InvalidOperationException("Sensitive failure details.");
        var connectionProvider = new PostgresTransactionManager(_ => throw exception);
        var diagnostics = new PostgresAuthenticationRateLimiterDiagnostics(
            connectionProvider,
            Options.Create(new PostgresAuthenticationRateLimiterOptions()),
            _timeProvider,
            NullLogger<PostgresAuthenticationRateLimiterDiagnostics>.Instance);

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
}
