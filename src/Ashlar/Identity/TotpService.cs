using System.Security.Cryptography;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Totp;
using Ashlar.Security;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

/// <summary>
/// Implements TOTP (Time-based One-Time Password) enrollment and management.
/// </summary>
public sealed class TotpService : ITotpService
{
    private readonly IIdentityRepository _repository;
    private readonly ICredentialService _credentialService;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IAuthenticationProvider _provider;
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly SecurityNotificationEmitter _notifications;

    public TotpService(
        IIdentityRepository repository,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        IEnumerable<IAuthenticationProvider> providers,
        TotpServiceDependencies dependencies)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
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

    public TotpService(
        IIdentityRepository repository,
        ICredentialService credentialService,
        IAshlarTransactionProvider transactionProvider,
        IEnumerable<IAuthenticationProvider> providers,
        IOptions<TotpOptions> options,
        TimeProvider? timeProvider = null,
        ISecurityEventSink? securityEventSink = null)
        : this(repository, credentialService, transactionProvider, providers, new TotpServiceDependencies(options, timeProvider, securityEventSink))
    {
    }

    /// <inheritdoc />
    public async Task<TotpEnrollment> StartEnrollmentAsync(Guid userId, string issuer, string accountName, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountName);

        var secretBytes = RandomNumberGenerator.GetBytes(_options.SecretLengthBytes);
        var base32Secret = Base32.Encode(secretBytes);

        var uri = TotpAuthenticator.CreateOtpAuthUri("totp", base32Secret, accountName, issuer, _options.CodeDigits, _options.StepSeconds);

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.TotpEnrollmentStarted,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            Provider = _options.ProviderKey
        }, cancellationToken);

        return new TotpEnrollment(base32Secret, uri);
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAndEnrollAsync(Guid userId, string sharedSecret, string code, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        if (string.IsNullOrWhiteSpace(code)) return false;
        if (string.IsNullOrWhiteSpace(sharedSecret) || sharedSecret.Length > 256) return false;

        if (!Base32.TryDecode(sharedSecret, out var secretBytes) || secretBytes.Length < 16)
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow();

        var (verified, verifiedStep) = TotpAuthenticator.VerifyTotp(secretBytes, code, now, _options.StepSeconds, _options.CodeDigits, _options.AllowedSkewSteps);

        if (!verified)
        {
            return false;
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        // Replace any existing TOTP credential for this user.
        await _repository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);

        var assertion = new TotpAssertion(code);
        var initialMetadata = System.Text.Json.JsonSerializer.Serialize(new { LastUsedStep = verifiedStep });
        await _credentialService.LinkCredentialAsync(userId, assertion, _provider, sharedSecret, initialMetadata, cancellationToken);

        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpEnrollmentCompleted,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                Provider = _options.ProviderKey
            }, ct);

            var user = await _repository.GetUserByIdAsync(userId, ct);
            if (user != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.TotpEnrolled, user, now, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return true;

    }

    /// <inheritdoc />
    public async Task<bool> DisableTotpAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var count = await _repository.RevokeCredentialsAsync(userId, _options.ProviderKey.Type, _options.ProviderKey.Name, cancellationToken);
        if (count == 0) return false;

        var now = _timeProvider.GetUtcNow();
        transaction.OnCommitted(async ct =>
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.TotpDisabled,
                Outcome = SecurityEventOutcomes.Success,
                UserId = userId,
                Provider = _options.ProviderKey
            }, ct);

            var user = await _repository.GetUserByIdAsync(userId, ct);
            if (user != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.TotpDisabled, user, now, cancellationToken: ct);
            }
        });

        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}

public sealed class TotpServiceDependencies(
    IOptions<TotpOptions> options,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null,
    ISecurityNotificationService? notificationService = null)
{
    public IOptions<TotpOptions> Options { get; } = options ?? throw new ArgumentNullException(nameof(options));
    public TimeProvider TimeProvider { get; } = timeProvider ?? TimeProvider.System;
    public ISecurityEventSink? SecurityEventSink { get; } = securityEventSink;
    public ISecurityNotificationService? NotificationService { get; } = notificationService;
}
