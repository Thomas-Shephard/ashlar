using Ashlar.Operational.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Redis.RateLimiting;

internal sealed class RedisAuthenticationRateLimiterDiagnostics : IAuthenticationRateLimiterDiagnostics
{
    private const string ProviderName = "Redis";

    private static readonly Action<ILogger, Exception?> RateLimiterDiagnosticsFailed =
        LoggerMessage.Define(
            LogLevel.Error,
            new EventId(1010, nameof(RateLimiterDiagnosticsFailed)),
            "Redis authentication rate limiter diagnostics failed.");

    private readonly RedisAuthenticationRateLimiterConnection _connection;
    private readonly RedisAuthenticationRateLimiterOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<RedisAuthenticationRateLimiterDiagnostics> _logger;

    public RedisAuthenticationRateLimiterDiagnostics(
        RedisAuthenticationRateLimiterConnection connection,
        IOptions<RedisAuthenticationRateLimiterOptions> options,
        TimeProvider timeProvider,
        ILogger<RedisAuthenticationRateLimiterDiagnostics>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _connection = connection;
        _options = options.Value;
        if (!RedisAuthenticationRateLimiterOptions.Validate(_options))
        {
            throw new ArgumentException("Redis rate limiter options are invalid.", nameof(options));
        }

        _timeProvider = timeProvider;
        _logger = logger ?? NullLogger<RedisAuthenticationRateLimiterDiagnostics>.Instance;
    }

    public async Task<AuthenticationRateLimiterDiagnosticResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var checkedAt = _timeProvider.GetUtcNow();
        try
        {
            var connection = await _connection.GetConnectionAsync();
            var database = connection.GetDatabase(_options.Database ?? -1);
            await database.PingAsync();
            cancellationToken.ThrowIfCancellationRequested();

            return new AuthenticationRateLimiterDiagnosticResult(
                AshlarDiagnosticStatus.Healthy,
                ProviderName,
                null,
                checkedAt,
                true,
                true,
                _options.Persistent,
                null,
                null,
                null,
                false,
                null,
                null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            RateLimiterDiagnosticsFailed(_logger, ex);
            return new AuthenticationRateLimiterDiagnosticResult(
                AshlarDiagnosticStatus.Unknown,
                ProviderName,
                "Authentication rate limiter diagnostics could not query provider state.",
                checkedAt,
                true,
                true,
                _options.Persistent,
                null,
                null,
                null,
                false,
                null,
                null);
        }
    }
}
