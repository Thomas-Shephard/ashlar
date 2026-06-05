using Ashlar.Auditing;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.AccountLockout;

/// <summary>
/// Provides automatic account lockout behavior for resolved users.
/// </summary>
/// <param name="repository">The durable lockout repository.</param>
/// <param name="options">The lockout options.</param>
/// <param name="dependencies">Optional operational dependencies.</param>
public sealed class AccountLockoutService(
    IAccountLockoutRepository repository,
    IOptions<AccountLockoutOptions> options,
    AccountLockoutServiceDependencies? dependencies = null) : IAccountLockoutService
{
    private readonly IAccountLockoutRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly AccountLockoutOptions _options = ValidateOptions(options);
    private readonly TimeProvider _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(dependencies?.SecurityEventSink, dependencies?.TimeProvider ?? TimeProvider.System);

    /// <inheritdoc />
    public async Task<AccountLockoutStatus> GetStatusAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ValidateUser(user);
        ValidateProvider(provider);
        var tenantId = GetTenantId(user, context);
        var record = await _repository.GetAsync(user.Id, tenantId, provider, cancellationToken);
        return ToStatus(user.Id, tenantId, provider, record, _timeProvider.GetUtcNow());
    }

    /// <inheritdoc />
    public async Task<AccountLockoutFailureResult> RecordFailureAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ValidateUser(user);
        ValidateProvider(provider);
        var tenantId = GetTenantId(user, context);
        var now = _timeProvider.GetUtcNow();
        var update = await _repository.RecordFailureAsync(
            user.Id,
            tenantId,
            provider,
            now,
            _options.FailureThreshold,
            _options.LockoutDuration,
            cancellationToken);
        var record = update.Record;
        var status = ToStatus(user.Id, tenantId, provider, record, now);
        var lockoutActivated = update.LockoutActivated;
        if (lockoutActivated)
        {
            await RecordLockoutActivatedAsync(user.Id, tenantId, provider, record, context, cancellationToken);
        }

        return new AccountLockoutFailureResult(
            status,
            record.FailedAttemptCount >= _options.FailureThreshold,
            lockoutActivated);
    }

    /// <inheritdoc />
    public Task<bool> ResetAsync(
        IUser user,
        AuthenticationProviderKey provider,
        AccountLockoutContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ValidateUser(user);
        ValidateProvider(provider);
        var tenantId = GetTenantId(user, context);
        return _repository.ResetAsync(user.Id, tenantId, provider, cancellationToken);
    }

    private static AccountLockoutOptions ValidateOptions(IOptions<AccountLockoutOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!AccountLockoutOptions.Validate(options.Value))
        {
            throw new ArgumentException("Account lockout options are invalid.", nameof(options));
        }

        return options.Value;
    }

    private static void ValidateUser(IUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.Id == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(user));
        }
    }

    private static void ValidateProvider(AuthenticationProviderKey provider)
    {
        if (provider.Type == default || string.IsNullOrWhiteSpace(provider.Name))
        {
            throw new ArgumentException("Provider key must be fully initialized.", nameof(provider));
        }
    }

    private static Guid? GetTenantId(IUser user, AccountLockoutContext? context)
    {
        var actualTenantId = (user as ITenantUser)?.TenantId;
        if (context?.Tenant == null)
        {
            return actualTenantId;
        }

        if (actualTenantId != context.Tenant.TenantId)
        {
            throw new InvalidOperationException("Lockout tenant scope must match the resolved user.");
        }

        return actualTenantId;
    }

    private static bool IsLocked(AccountLockoutRecord record, DateTimeOffset now)
    {
        if (record.LockedUntil is not { } lockedUntil)
        {
            return false;
        }

        return lockedUntil > now;
    }

    private static AccountLockoutStatus ToStatus(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        AccountLockoutRecord? record,
        DateTimeOffset now)
    {
        if (record == null)
        {
            return AccountLockoutStatus.None(userId, tenantId, provider);
        }

        return new AccountLockoutStatus(
            userId,
            tenantId,
            provider,
            record.FailedAttemptCount,
            record.FirstFailedAt,
            record.LastFailedAt,
            record.LockedUntil,
            IsLocked(record, now));
    }

    private Task RecordLockoutActivatedAsync(
        Guid userId,
        Guid? tenantId,
        AuthenticationProviderKey provider,
        AccountLockoutRecord record,
        AccountLockoutContext? context,
        CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AccountLockoutActivated,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenantId,
            Audit = context?.Audit,
            Provider = provider,
            FailureReason = SecurityEventFailureReasons.AutomaticAccountLockout,
            Properties = new Dictionary<string, string>
            {
                ["failed_attempt_count"] = record.FailedAttemptCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["locked_until"] = record.LockedUntil.GetValueOrDefault().ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            }
        }, cancellationToken);
    }
}

/// <summary>
/// Optional dependencies for <see cref="AccountLockoutService" />.
/// </summary>
/// <param name="TimeProvider">The optional clock.</param>
/// <param name="SecurityEventSink">The optional security event sink.</param>
public sealed record AccountLockoutServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null);
