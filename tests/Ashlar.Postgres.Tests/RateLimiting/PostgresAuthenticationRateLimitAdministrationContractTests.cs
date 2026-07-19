using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Ashlar.Testing;

namespace Ashlar.Postgres.Tests.RateLimiting;

internal sealed class PostgresAuthenticationRateLimitAdministrationContractTests : AuthenticationRateLimitAdministrationContractTests
{
    private static readonly DateTimeOffset Start = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private PostgresContractDatabaseLease? _database;
    private FakeTimeProvider _timeProvider = null!;

    protected override DateTimeOffset Now => _timeProvider.GetUtcNow();

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _timeProvider = new FakeTimeProvider(Start);
        _database = await PostgresContractDatabase.CreateInitializedServiceProviderAsync(services =>
        {
            services.AddAshlarIdentity();
            services.AddAshlarPostgresRateLimiting();
            services.AddScoped<IAccountSecurityOperationAuthorizer, AllowAccountSecurityOperationAuthorizer>();
            services.AddSingleton<TimeProvider>(_timeProvider);
        });
        return _database.ServiceProvider;
    }

    protected override async Task CleanupInitializedServiceProviderAsync()
    {
        if (_database != null)
        {
            await _database.DropDatabaseAsync();
            _database = null;
        }
    }

    protected override void AdvanceTime(TimeSpan duration)
    {
        _timeProvider.Advance(duration);
    }

    [Test]
    public void AdministrationRepositoryConstructorValidatesDataSource()
    {
        Assert.Throws<ArgumentNullException>(() => _ = new PostgresAuthenticationRateLimitAdministrationRepository(null!));
    }
}
