using System.Security.Cryptography;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Implements TOTP (Time-based One-Time Password) enrollment and management.
/// </summary>
public sealed class TotpService : ITotpService
{
    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly ICredentialService _credentialService;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IAuthenticationProvider _provider;
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="userRepository">Stores and retrieves users.</param>
    /// <param name="credentialRepository">Stores and retrieves credentials.</param>
    /// <param name="credentialService">The credential service value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="providers">The providers value.</param>
    /// <param name="dependencies">The dependencies value.</param>
    public TotpService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        IEnumerable<IAuthenticationProvider> providers,
        TotpServiceDependencies dependencies)
    {
        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
        _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        ArgumentNullException.ThrowIfNull(dependencies);
        _options = dependencies.Options.Value;
        TotpOptions.ThrowIfInvalid(_options);
        _timeProvider = dependencies.TimeProvider;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider);
        _notifications = new SecurityNotificationEmitter(dependencies.NotificationService);
        _provider = providers.OfType<TotpAuthenticationProvider>().FirstOrDefault()
            ?? throw new InvalidOperationException($"Required provider '{nameof(TotpAuthenticationProvider)}' not registered.");
    }

    /// <inheritdoc />
    public async Task<TotpEnrollment> StartEnrollmentAsync(Guid userId, string issuer, string accountName, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
        tenant ??= TenantContext.Global;

        var secretBytes = RandomNumberGenerator.GetBytes(_options.SecretLengthBytes);
        var base32Secret = Base32.Encode(secretBytes);

        var uri = TotpAuthenticator.CreateOtpAuthUri("totp", base32Secret, accountName, issuer, _options.CodeDigits, _options.StepSeconds);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentStarted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey
        }, cancellationToken);

        return new TotpEnrollment(base32Secret, uri);
    }

    /// <inheritdoc />
    public async Task<Result> VerifyAndEnrollAsync(Guid userId, string sharedSecret, string code, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        tenant ??= TenantContext.Global;

        if (string.IsNullOrWhiteSpace(code))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.EmptyCode.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.EmptyCode);
        }

        if (string.IsNullOrWhiteSpace(sharedSecret) || sharedSecret.Length > 256)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidSecret.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidSecret);
        }

        if (!Base32.TryDecode(sharedSecret, out var secretBytes) || secretBytes.Length < 16)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidSecretFormat.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidSecretFormat);
        }

        var now = _timeProvider.GetUtcNow();

        var (verified, verifiedStep) = TotpAuthenticator.VerifyTotp(secretBytes, code, now, _options.StepSeconds, _options.CodeDigits, _options.AllowedSkewSteps);

        if (!verified)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidCode.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidCode);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        // Replace any existing TOTP credential for this user.
        await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        var assertion = new TotpAssertion(code);
        var totpCredentialMetadata = System.Text.Json.JsonSerializer.Serialize(new { LastUsedStep = verifiedStep });
        var linkResult = await _credentialService.LinkCredentialAsync(userId, assertion, _provider, sharedSecret, totpCredentialMetadata, cancellationToken);

        if (!linkResult.Succeeded)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey,
                FailureReason = linkResult.FailureCode?.Value ?? AshlarFailureCodes.LinkFailed.Value
            }, cancellationToken);
            return Result.Failure(linkResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.LinkFailed));
        }

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey
            }, ct);

            var user = await _userRepository.GetUserByIdAsync(userId, ct);
            if (user != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.TotpEnrolled, user, now, context: ToNotificationContext(audit), cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    /// <inheritdoc />
    public async Task<bool> DisableTotpAsync(Guid userId, TenantContext? tenant = null, AuditContext? audit = null, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        tenant ??= TenantContext.Global;

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var count = await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
        if (count == 0) return false;

        var now = _timeProvider.GetUtcNow();
        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpDisabled,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = audit,
                Provider = _options.ProviderKey
            }, ct);

            var user = await _userRepository.GetUserByIdAsync(userId, ct);
            if (user != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.TotpDisabled, user, now, context: ToNotificationContext(audit), cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return true;
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
/// Provides totp service dependencies behavior.
/// </summary>
/// <param name="options">The options value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
/// <param name="notificationService">The notification service value.</param>
public sealed class TotpServiceDependencies(
    IOptions<TotpOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IOptions<TotpOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    /// <summary>
    /// Gets or sets the time provider value.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    /// <summary>
    /// Gets or sets the security event sink value.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    /// <summary>
    /// Gets or sets the notification service value.
    /// </summary>
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
