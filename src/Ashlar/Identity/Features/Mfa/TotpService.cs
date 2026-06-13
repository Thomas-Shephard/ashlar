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
    /// <param name="credentialService">Credential lifecycle service used to persist TOTP credentials.</param>
    /// <param name="transactionProvider">Transaction provider used for enrollment and disable mutations.</param>
    /// <param name="providers">Authentication providers used to locate the configured TOTP provider.</param>
    /// <param name="dependencies">TOTP options, audit, clock, and notification dependencies.</param>
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
    public async Task<TotpEnrollment> StartEnrollmentAsync(StartTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var userId = request.ActorUserId;
        if (userId == Guid.Empty) throw new ArgumentException("Actor user ID cannot be empty.", $"{nameof(request)}.{nameof(request.ActorUserId)}");
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.AccountName);
        var tenant = request.Tenant ?? TenantContext.Global;

        await ValidateUserTenantAsync(userId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentStarted, throwOnFailure: true, cancellationToken);

        var secretBytes = RandomNumberGenerator.GetBytes(_options.SecretLengthBytes);
        var base32Secret = Base32.Encode(secretBytes);

        var uri = TotpAuthenticator.CreateOtpAuthUri("totp", base32Secret, request.AccountName, request.Issuer, _options.CodeDigits, _options.StepSeconds);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentStarted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = request.Audit,
            Provider = _options.ProviderKey
        }, cancellationToken);

        return new TotpEnrollment(base32Secret, uri);
    }

    /// <inheritdoc />
    public async Task<Result> CompleteEnrollmentAsync(VerifyTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var userId = request.ActorUserId;
        if (userId == Guid.Empty) throw new ArgumentException("Actor user ID cannot be empty.", $"{nameof(request)}.{nameof(request.ActorUserId)}");
        var tenant = request.Tenant ?? TenantContext.Global;

        if (string.IsNullOrWhiteSpace(request.Code))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.EmptyCode.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.EmptyCode);
        }

        if (string.IsNullOrWhiteSpace(request.SharedSecret) || request.SharedSecret.Length > 256)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidSecret.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidSecret);
        }

        if (!Base32.TryDecode(request.SharedSecret, out var secretBytes) || secretBytes.Length < 16)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidSecretFormat.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidSecretFormat);
        }

        var userResult = await ValidateUserTenantAsync(userId, tenant, request.Audit, AshlarSecurityEventTypes.TotpEnrollmentCompleted, throwOnFailure: false, cancellationToken);
        if (!userResult.Succeeded)
        {
            return Result.Failure(userResult.FailureDetails!);
        }

        var now = _timeProvider.GetUtcNow();

        var (verified, verifiedStep) = TotpAuthenticator.VerifyTotp(secretBytes, request.Code, now, _options.StepSeconds, _options.CodeDigits, _options.AllowedSkewSteps);

        if (!verified)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
                Provider = _options.ProviderKey,
                FailureReason = AshlarFailureCodes.InvalidCode.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidCode);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        // Replace any existing TOTP credential for this user.
        await _credentialRepository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        var assertion = new TotpAssertion(request.Code);
        var totpCredentialMetadata = System.Text.Json.JsonSerializer.Serialize(new { LastUsedStep = verifiedStep });
        var linkResult = await _credentialService.LinkCredentialAsync(userId, assertion, _provider, request.SharedSecret, totpCredentialMetadata, cancellationToken);

        if (!linkResult.Succeeded)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                TenantId = tenant.TenantId,
                Audit = request.Audit,
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
                Audit = request.Audit,
                Provider = _options.ProviderKey
            }, ct);

            await _notifications.NotifyAsync(SecurityNotificationType.TotpEnrolled, userResult.Value!, now, context: ToNotificationContext(request.Audit), cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    /// <inheritdoc />
    public async Task<bool> DisableAsync(DisableTotpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var userId = request.ActorUserId;
        if (userId == Guid.Empty) throw new ArgumentException("Actor user ID cannot be empty.", $"{nameof(request)}.{nameof(request.ActorUserId)}");
        var tenant = request.Tenant ?? TenantContext.Global;

        var userResult = await ValidateUserTenantAsync(userId, tenant, request.Audit, AshlarSecurityEventTypes.TotpDisabled, throwOnFailure: false, cancellationToken);
        if (!userResult.Succeeded)
        {
            return false;
        }

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
                Audit = request.Audit,
                Provider = _options.ProviderKey
            }, ct);

            await _notifications.NotifyAsync(SecurityNotificationType.TotpDisabled, userResult.Value!, now, context: ToNotificationContext(request.Audit), cancellationToken: ct);
        });

        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private async Task<Result<IUser>> ValidateUserTenantAsync(
        Guid userId,
        TenantContext tenant,
        AuditContext? audit,
        string eventType,
        bool throwOnFailure,
        CancellationToken cancellationToken)
    {
        var result = await UserTenantValidator.GetUserInTenantAsync(_userRepository, userId, tenant, cancellationToken);
        if (result.Succeeded)
        {
            return result;
        }

        var failureCode = result.FailureCode!.Value;
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = tenant.TenantId,
            Audit = audit,
            Provider = _options.ProviderKey,
            FailureReason = failureCode.Value
        }, cancellationToken);

        if (throwOnFailure)
        {
            throw new AshlarOperationException(failureCode, "TOTP user validation failed for the requested tenant.");
        }

        return result;
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
/// Groups optional dependencies used by the TOTP service.
/// </summary>
/// <param name="options">TOTP configuration options.</param>
/// <param name="timeProvider">Clock used for timestamps and TOTP verification windows.</param>
/// <param name="securityEventSink">Optional sink used to record TOTP security events.</param>
/// <param name="notificationService">Optional service used to send account security notifications.</param>
public sealed class TotpServiceDependencies(
    IOptions<TotpOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    /// <summary>
    /// Gets TOTP configuration options.
    /// </summary>
    public IOptions<TotpOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    /// <summary>
    /// Gets the clock used for timestamps and TOTP verification windows.
    /// </summary>
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    /// <summary>
    /// Gets the optional sink used to record TOTP security events.
    /// </summary>
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    /// <summary>
    /// Gets the optional service used to send account security notifications.
    /// </summary>
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
