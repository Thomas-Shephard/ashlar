using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Providers.RecoveryCode;

/// <summary>
/// Implements services for managing user recovery codes.
/// </summary>
public sealed class RecoveryCodeService : IRecoveryCodeService
{
    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly Security.Hashing.PasswordHasherSelector _hasherSelector;
    private readonly RecoveryCodeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="userRepository">Stores and retrieves users.</param>
    /// <param name="credentialRepository">Stores and retrieves credentials.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="hasherSelector">The hasher selector value.</param>
    /// <param name="dependencies">Options and operational dependencies used by recovery-code flows.</param>
    public RecoveryCodeService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        IAshlarTransactionProvider transactionProvider,
        Security.Hashing.PasswordHasherSelector hasherSelector,
        RecoveryCodeServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(userRepository);
        ArgumentNullException.ThrowIfNull(credentialRepository);
        ArgumentNullException.ThrowIfNull(transactionProvider);
        ArgumentNullException.ThrowIfNull(hasherSelector);
        ArgumentNullException.ThrowIfNull(dependencies);
        ArgumentNullException.ThrowIfNull(dependencies.Options.Value);

        _userRepository = userRepository;
        _credentialRepository = credentialRepository;
        _transactionProvider = transactionProvider;
        _hasherSelector = hasherSelector;
        _options = dependencies.Options.Value;
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider);
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
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
        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
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
            await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
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

            await _credentialRepository.CreateCredentialAsync(credential, cancellationToken);
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

        var count = await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

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

/// <summary>
/// Optional dependencies used by recovery-code service operations.
/// </summary>
/// <param name="options">Recovery-code options.</param>
/// <param name="timeProvider">Clock used for recovery-code timestamps.</param>
/// <param name="securityEventSink">Receives recovery-code security events.</param>
/// <param name="notificationService">Sends recovery-code security notifications.</param>
public sealed class RecoveryCodeServiceDependencies(
    IOptions<RecoveryCodeOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    /// <summary>
    /// Gets the configured recovery-code options.
    /// </summary>
    public IOptions<RecoveryCodeOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Gets the clock used for recovery-code timestamps.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Gets the sink used to record recovery-code security events.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;

    /// <summary>
    /// Gets the service used to send recovery-code security notifications.
    /// </summary>
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
