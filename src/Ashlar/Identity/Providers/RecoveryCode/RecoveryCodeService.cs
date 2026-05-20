using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Implements services for managing user recovery codes.
/// </summary>
public sealed class RecoveryCodeService : IRecoveryCodeService
{
    private readonly IIdentityRepository _repository;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly Security.Hashing.PasswordHasherSelector _hasherSelector;
    private readonly RecoveryCodeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="repository">The repository value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="hasherSelector">The hasher selector value.</param>
    /// <param name="options">The options value.</param>
    /// <param name="timeProvider">The time provider value.</param>
    /// <param name="securityEventSink">The security event sink value.</param>
    /// <param name="notificationService">The notification service value.</param>
    public RecoveryCodeService(
        IIdentityRepository repository,
        IAshlarTransactionProvider transactionProvider,
        Security.Hashing.PasswordHasherSelector hasherSelector,
        IOptions<RecoveryCodeOptions> options,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null,
        ISecurityNotificationService? notificationService = null)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(transactionProvider);
        ArgumentNullException.ThrowIfNull(hasherSelector);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.Value);

        _repository = repository;
        _transactionProvider = transactionProvider;
        _hasherSelector = hasherSelector;
        _options = options.Value;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(securityEventSink, _timeProvider);
        _notifications = new SecurityNotificationEmitter(notificationService);
    }

    /// <inheritdoc />
    public async Task<Result<IReadOnlyList<string>>> GenerateRecoveryCodesAsync(Guid userId, RecoveryCodeGenerationRequest? request = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }

        request ??= new RecoveryCodeGenerationRequest();
        var tenant = request.Tenant ?? TenantContext.Global;
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        // Verify user exists
        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.UserNotFound.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.UserNotFound);
        }

        var codeCount = request.CodeCount ?? _options.CodeCount;
        if (codeCount <= 0 || codeCount > _options.CodeCount * 2)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidCodeCount.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidCodeCount);
        }

        if (_options.CodeLength <= 0 || _options.GroupSize <= 0)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidConfiguration.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidConfiguration);
        }

        var expiresAfter = request.ExpiresAfter ?? _options.ExpiresAfter;
        if (expiresAfter.HasValue && expiresAfter.Value <= TimeSpan.Zero)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidExpiry.Value
            }, cancellationToken);
            return Result.Failure<IReadOnlyList<string>>(AshlarFailureCodes.InvalidExpiry);
        }

        // Revoke existing recovery codes if requested
        if (request.ReplaceExisting)
        {
            await _repository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
        }

        var rawCodes = new List<string>();
        var now = _timeProvider.GetUtcNow();
        var expiresAt = expiresAfter.HasValue ? now.Add(expiresAfter.Value) : (DateTimeOffset?)null;

        for (int i = 0; i < codeCount; i++)
        {
            var idCode = RecoveryCodeGenerator.GenerateCode(5, 5);
            var secretCode = RecoveryCodeGenerator.GenerateCode(_options.CodeLength, _options.GroupSize);
            var rawCode = $"{idCode}-{secretCode}";
            rawCodes.Add(rawCode);

            var hashedCode = PasswordCredentialHashing.HashToBase64(_hasherSelector, secretCode);

            var credential = new UserCredential
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ProviderType = _options.ProviderKey.Type,
                ProviderName = _options.ProviderKey.Name,
                ProviderKey = $"{userId:N}-{idCode}",
                CredentialValue = hashedCode,
                Purpose = "recovery-code",
                Status = CredentialStatus.Active,
                CreatedAt = now,
                Version = Guid.NewGuid().ToString("N"),
                ExpiresAt = expiresAt
            };

            await _repository.CreateCredentialAsync(credential, cancellationToken);
        }

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.RecoveryCodesGenerated,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                Properties = new Dictionary<string, string>
                {
                    ["count"] = codeCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
                }
            }, ct);

            await _notifications.NotifyAsync(SecurityNotificationType.RecoveryCodesGenerated, user, now, context: ToNotificationContext(request.Audit), metadata: new Dictionary<string, string>
            {
                ["count"] = codeCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }, cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);

        return Result.Success<IReadOnlyList<string>>(rawCodes);
    }

    /// <inheritdoc />
    public async Task<int> RevokeRecoveryCodesAsync(Guid userId, string? reason = null, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }
        tenant ??= TenantContext.Global;

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var count = await _repository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RecoveryCodesRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            Properties = reason != null ? new Dictionary<string, string> { ["reason"] = reason } : null
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return count;
    }

    private static AuthenticationContext? ToNotificationContext(AuditContext? audit)
    {
        if (audit == null) return new AuthenticationContext();

        return new AuthenticationContext(
            UserId: audit.ActorUserId,
            IpAddress: audit.IpAddress,
            UserAgent: audit.UserAgent,
            CorrelationId: audit.CorrelationId);
    }
}
