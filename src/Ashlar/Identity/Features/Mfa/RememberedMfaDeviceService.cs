using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Ashlar.Auditing;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Implements remembered MFA device lifecycle operations.
/// </summary>
public sealed class RememberedMfaDeviceService : IRememberedMfaDeviceService
{
    private static readonly Action<ILogger, Guid, Guid, Exception?> LastUsedUpdateNotPersisted =
        LoggerMessage.Define<Guid, Guid>(
            LogLevel.Information,
            new EventId(1000, nameof(LastUsedUpdateNotPersisted)),
            "Remembered MFA device last-used update was not persisted. DeviceId={DeviceId} UserId={UserId}");

    private const char TokenSeparator = '.';
    private const int MaxTokenPartLength = 512;
    private readonly IRememberedMfaDeviceRepository _repository;
    private readonly IUserRepository _userRepository;
    private readonly ISecureTokenGenerator _tokenGenerator;
    private readonly ISecureTokenHasher _tokenHasher;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly RememberedMfaDeviceOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly ILogger<RememberedMfaDeviceService> _logger;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="repository">The remembered device repository.</param>
    /// <param name="userRepository">The user repository.</param>
    /// <param name="tokenGenerator">The secure token generator.</param>
    /// <param name="tokenHasher">The secure token hasher.</param>
    /// <param name="transactionProvider">The transaction provider.</param>
    /// <param name="dependencies">The service dependencies.</param>
    /// <param name="logger">The logger.</param>
    public RememberedMfaDeviceService(
        IRememberedMfaDeviceRepository repository,
        IUserRepository userRepository,
        ISecureTokenGenerator tokenGenerator,
        ISecureTokenHasher tokenHasher,
        IAshlarTransactionProvider transactionProvider,
        RememberedMfaDeviceServiceDependencies dependencies,
        ILogger<RememberedMfaDeviceService>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(dependencies);
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
        _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _options = ValidateOptions(dependencies.Options?.Value ?? new RememberedMfaDeviceOptions());
        _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider, dependencies.LoggerFactory);
        _logger = logger ?? NullLogger<RememberedMfaDeviceService>.Instance;
    }

    public async Task<Result<RememberedMfaDeviceCreated>> CreateAsync(Guid userId, CreateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        var tenant = request.Tenant ?? TenantContext.Global;
        var displayName = ValidateOptionalLength(request.DisplayName, _options.MaxDisplayNameLength, $"{nameof(request)}.{nameof(request.DisplayName)}");
        var lifetime = ValidateLifetime(request.Lifetime ?? _options.DefaultLifetime, request.Lifetime, $"{nameof(request)}.{nameof(request.Lifetime)}");

        var userResult = await ValidateUserTenantAsync(userId, tenant, request.Audit, AshlarSecurityEventTypes.RememberedMfaDeviceCreated, cancellationToken);
        if (!userResult.Succeeded)
        {
            return Result.Failure<RememberedMfaDeviceCreated>(userResult.FailureDetails!);
        }

        var now = _timeProvider.GetUtcNow();
        if (DateTimeOffset.MaxValue - now < lifetime)
        {
            throw new ArgumentOutOfRangeException($"{nameof(request)}.{nameof(request.Lifetime)}", request.Lifetime, "Remembered MFA device lifetime exceeds the maximum representable expiry.");
        }

        var activeCount = await _repository.CountForUserAsync(userId, tenant, activeOnly: true, now, cancellationToken);
        if (activeCount >= _options.MaxActiveDevicesPerUser)
        {
            await RecordCreateRejectedAsync(userId, tenant, request.Audit, AshlarFailureCodes.RememberedMfaDeviceLimitExceeded, cancellationToken);
            return Result.Failure<RememberedMfaDeviceCreated>(AshlarFailureCodes.RememberedMfaDeviceLimitExceeded);
        }

        var selector = _tokenGenerator.GenerateToken(_options.SelectorByteLength);
        var verifier = _tokenGenerator.GenerateToken(_options.VerifierByteLength);
        var token = $"{selector}{TokenSeparator}{verifier}";
        var device = new RememberedMfaDevice
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenant.TenantId,
            TokenSelector = selector,
            TokenHash = _tokenHasher.HashToken(verifier),
            DisplayName = displayName,
            CreatedAt = now,
            ExpiresAt = now.Add(lifetime)
        };

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        await _repository.CreateAsync(device, cancellationToken);
        var summary = ToSummary(device, now);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RememberedMfaDeviceCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = request.Audit,
            Properties = new Dictionary<string, string> { ["remembered_device_id"] = device.Id.ToString("D") }
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(new RememberedMfaDeviceCreated(summary, token));
    }

    public async Task<ValidateRememberedMfaDeviceResult> ValidateAsync(Guid userId, ValidateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        var tenant = request.Tenant ?? TenantContext.Global;

        if (!TryParseToken(request.Token, out var selector, out var verifier)
            || !SecureTokenHashing.TryHashToken(_tokenHasher, verifier, out var verifierHash))
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.Failed, null, cancellationToken);
            return ValidateRememberedMfaDeviceResult.Failed;
        }

        var device = await _repository.GetByTokenSelectorAsync(selector, cancellationToken);
        var now = _timeProvider.GetUtcNow();
        if (device == null)
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.Failed, null, cancellationToken);
            return ValidateRememberedMfaDeviceResult.Failed;
        }

        if (!TokenHashesEqual(device.TokenHash, verifierHash))
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.Failed, device, cancellationToken);
            return ValidateRememberedMfaDeviceResult.Failed;
        }

        if (device.UserId != userId)
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.WrongUser, device, cancellationToken);
            return ValidateRememberedMfaDeviceResult.Failed;
        }

        if (device.TenantId != tenant.TenantId)
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.WrongTenant, device, cancellationToken);
            return ValidateRememberedMfaDeviceResult.Failed;
        }

        if (device.ExpiresAt <= now)
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.Expired, device, cancellationToken);
            return new ValidateRememberedMfaDeviceResult(false, ToSummary(device, now), RememberedMfaDeviceValidationStatus.Expired);
        }

        if (device.RevokedAt != null)
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.Revoked, device, cancellationToken);
            return new ValidateRememberedMfaDeviceResult(false, ToSummary(device, now), RememberedMfaDeviceValidationStatus.Revoked);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        if (!await TryUpdateLastUsedAsync(device, now, cancellationToken))
        {
            await RecordValidationRejectedAsync(userId, tenant, request.Audit, RememberedMfaDeviceValidationStatus.Failed, device, cancellationToken);
            return ValidateRememberedMfaDeviceResult.Failed;
        }

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RememberedMfaDeviceUsed,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = request.Audit,
            Properties = new Dictionary<string, string> { ["remembered_device_id"] = device.Id.ToString("D") }
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return new ValidateRememberedMfaDeviceResult(true, ToSummary(device, now), RememberedMfaDeviceValidationStatus.Success);
    }

    public async Task<IReadOnlyList<RememberedMfaDeviceSummary>> ListAsync(Guid userId, ListRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        var tenant = request.Tenant ?? TenantContext.Global;
        var now = _timeProvider.GetUtcNow();
        var devices = await _repository.ListForUserAsync(userId, tenant, request.ActiveOnly, now, cancellationToken);
        return devices.Select(device => ToSummary(device, now)).ToList().AsReadOnly();
    }

    public async Task<bool> RevokeAsync(Guid userId, RevokeRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        if (request.DeviceId == Guid.Empty) throw new ArgumentException("Device ID cannot be empty.", $"{nameof(request)}.{nameof(request.DeviceId)}");
        var reason = ValidateOptionalLength(request.Reason, _options.MaxRevocationReasonLength, $"{nameof(request)}.{nameof(request.Reason)}");

        var tenant = request.Tenant ?? TenantContext.Global;
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var revokedAt = _timeProvider.GetUtcNow();
        var revoked = await _repository.RevokeAsync(request.DeviceId, userId, revokedAt, reason, tenant, cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RememberedMfaDeviceRevoked,
            Outcome = revoked ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = request.Audit,
            FailureReason = revoked ? null : AshlarFailureCodes.InvalidOrExpiredTokenValue,
            Properties = CreateRevocationProperties(request.DeviceId, reason)
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return revoked;
    }

    public async Task<int> RevokeAllAsync(Guid userId, RevokeAllRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);
        var reason = ValidateOptionalLength(request.Reason, _options.MaxRevocationReasonLength, $"{nameof(request)}.{nameof(request.Reason)}");

        var tenant = request.Tenant ?? TenantContext.Global;
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var revokedAt = _timeProvider.GetUtcNow();
        var count = await _repository.RevokeAllForUserAsync(userId, revokedAt, reason, tenant, cancellationToken);
        var properties = new Dictionary<string, string> { ["count"] = count.ToString(CultureInfo.InvariantCulture) };
        if (reason != null)
        {
            properties["reason"] = reason;
        }

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RememberedMfaDevicesRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = request.Audit,
            Properties = properties
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return count;
    }

    private async Task<Result<IUser>> ValidateUserTenantAsync(Guid userId, TenantContext tenant, AuditContext? audit, string eventType, CancellationToken cancellationToken)
    {
        var result = await UserTenantValidator.GetUserInTenantAsync(_userRepository, userId, tenant, cancellationToken);
        if (result.Succeeded)
        {
            return result;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            FailureReason = result.FailureCode!.Value.Value
        }, cancellationToken);

        return result;
    }

    private Task RecordValidationRejectedAsync(
        Guid userId,
        TenantContext tenant,
        AuditContext? audit,
        RememberedMfaDeviceValidationStatus status,
        RememberedMfaDevice? device,
        CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RememberedMfaDeviceRejected,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            FailureReason = status.ToString(),
            Properties = device == null
                ? new Dictionary<string, string> { ["status"] = status.ToString() }
                : new Dictionary<string, string> { ["status"] = status.ToString(), ["remembered_device_id"] = device.Id.ToString("D") }
        }, cancellationToken);
    }

    private Task RecordCreateRejectedAsync(
        Guid userId,
        TenantContext tenant,
        AuditContext? audit,
        AshlarFailureCode failureCode,
        CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.RememberedMfaDeviceCreated,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            FailureReason = failureCode.Value
        }, cancellationToken);
    }

    private async Task<bool> TryUpdateLastUsedAsync(RememberedMfaDevice device, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var updated = await _repository.UpdateLastUsedAsync(device.Id, now, cancellationToken);
        if (updated)
        {
            device.LastUsedAt = now;
            return true;
        }

        LastUsedUpdateNotPersisted(_logger, device.Id, device.UserId, null);
        return false;
    }

    private static Dictionary<string, string> CreateRevocationProperties(Guid deviceId, string? reason)
    {
        var properties = new Dictionary<string, string> { ["remembered_device_id"] = deviceId.ToString("D") };
        if (reason != null)
        {
            properties["reason"] = reason;
        }

        return properties;
    }

    private static bool TryParseToken(string? token, out string selector, out string verifier)
    {
        selector = string.Empty;
        verifier = string.Empty;
        if (string.IsNullOrWhiteSpace(token) || token.Length > MaxTokenPartLength * 2 + 1)
        {
            return false;
        }

        var separatorIndex = token.IndexOf(TokenSeparator, StringComparison.Ordinal);
        if (separatorIndex <= 0 || separatorIndex != token.LastIndexOf(TokenSeparator))
        {
            return false;
        }

        selector = token[..separatorIndex];
        verifier = token[(separatorIndex + 1)..];
        return selector.Length <= MaxTokenPartLength
            && verifier.Length <= MaxTokenPartLength
            && !string.IsNullOrWhiteSpace(selector)
            && !string.IsNullOrWhiteSpace(verifier);
    }

    private static bool TokenHashesEqual(string storedHash, string suppliedHash)
    {
        return CryptographicOperations.FixedTimeEquals(
            MemoryMarshal.AsBytes(storedHash.AsSpan()),
            MemoryMarshal.AsBytes(suppliedHash.AsSpan()));
    }

    private static RememberedMfaDeviceSummary ToSummary(RememberedMfaDevice device, DateTimeOffset now)
    {
        return new RememberedMfaDeviceSummary(
            device.Id,
            device.UserId,
            device.TenantId,
            device.DisplayName,
            device.CreatedAt,
            device.LastUsedAt,
            device.ExpiresAt,
            device.RevokedAt,
            device.RevocationReason,
            device.IsActive(now));
    }

    private static string? ValidateOptionalLength(string? value, int maxLength, string parameterName)
    {
        if (value == null)
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (trimmed.Length > maxLength)
        {
            throw new ArgumentException($"{parameterName} cannot exceed {maxLength} characters.", parameterName);
        }

        return trimmed;
    }

    private static RememberedMfaDeviceOptions ValidateOptions(RememberedMfaDeviceOptions options)
    {
        if (!RememberedMfaDeviceOptions.Validate(options))
        {
            throw new ArgumentException("Remembered MFA device options are invalid.", nameof(options));
        }

        return options;
    }

    private TimeSpan ValidateLifetime(TimeSpan lifetime, TimeSpan? requestedLifetime, string parameterName)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > _options.MaxLifetime)
        {
            throw new ArgumentOutOfRangeException(parameterName, requestedLifetime, "Remembered MFA device lifetime must be positive and no greater than the configured maximum.");
        }

        return lifetime;
    }
}

/// <summary>
/// Dependencies for <see cref="RememberedMfaDeviceService" />.
/// </summary>
/// <param name="Options">The configured options.</param>
/// <param name="TimeProvider">The time provider.</param>
/// <param name="SecurityEventSink">The security event sink.</param>
/// <param name="LoggerFactory">The logger factory.</param>
public sealed record RememberedMfaDeviceServiceDependencies(
    IOptions<RememberedMfaDeviceOptions>? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    ILoggerFactory? LoggerFactory = null);
