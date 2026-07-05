using System.Collections.Concurrent;
using Ashlar.Auditing;
using Ashlar.Security.Encryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ashlar.Identity.Features.Credentials;

internal sealed class CredentialService(
    IUserRepository userRepository,
    ICredentialRepository credentialRepository,
    ISecretProtector secretProtector,
    IAshlarTransactionProvider transactionProvider,
    CredentialServiceDependencies dependencies)
    : ICredentialService
{
    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CredentialProtectionFailedRequired =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Warning,
            new EventId(1000, nameof(CredentialProtectionFailedRequired)),
            "Credential value protection failed and required credential update cannot continue. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CredentialUpdateWipeRisk =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Warning,
            new EventId(1001, nameof(CredentialUpdateWipeRisk)),
            "Skipped credential update because it could wipe a protected credential value. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CredentialProtectionFailed =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Warning,
            new EventId(1002, nameof(CredentialProtectionFailed)),
            "Credential value protection failed. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CredentialUpdateConcurrencyConflict =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Warning,
            new EventId(1003, nameof(CredentialUpdateConcurrencyConflict)),
            "Credential update was not persisted due to a concurrency conflict. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CredentialUpdatePersistenceFailed =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Warning,
            new EventId(1004, nameof(CredentialUpdatePersistenceFailed)),
            "Credential update persistence failed. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, Guid, Guid, string, string, Exception?> CredentialUnprotectFailed =
        LoggerMessage.Define<Guid, Guid, string, string>(
            LogLevel.Warning,
            new EventId(1005, nameof(CredentialUnprotectFailed)),
            "Credential value unprotection failed. UserId={UserId} CredentialId={CredentialId} ProviderType={ProviderType} ProviderName={ProviderName}");

    private static readonly Action<ILogger, string, string, int, Exception?> DummyCredentialUnprotectFailed =
        LoggerMessage.Define<string, string, int>(
            LogLevel.Debug,
            new EventId(1006, nameof(DummyCredentialUnprotectFailed)),
            "Dummy credential unprotection failed during timing-resistant credential resolution. ProviderType={ProviderType} ProviderName={ProviderName} TypicalCredentialLength={TypicalCredentialLength}");

    private const string CredentialIdPropertyName = "credential_id";
    private readonly IUserRepository _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    private readonly ICredentialRepository _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
    private readonly ISecretProtector _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly IdentityServiceOptions _options = ValidateDependencies(dependencies).Options ?? new IdentityServiceOptions();
    private readonly TimeProvider _timeProvider = ValidateDependencies(dependencies).TimeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(
        ValidateDependencies(dependencies).SecurityEventSink,
        ValidateDependencies(dependencies).TimeProvider ?? TimeProvider.System);
    private readonly ILogger<CredentialService> _logger = ValidateDependencies(dependencies).Logger ?? NullLogger<CredentialService>.Instance;
    private readonly ConcurrentDictionary<int, string> _dummyValues = new();

    public CredentialService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        ISecretProtector secretProtector,
        IAshlarTransactionProvider transactionProvider)
        : this(userRepository, credentialRepository, secretProtector, transactionProvider, new CredentialServiceDependencies())
    {
    }

    private static CredentialServiceDependencies ValidateDependencies(CredentialServiceDependencies? dependencies)
    {
        return dependencies ?? throw new ArgumentNullException(nameof(dependencies));
    }

    public async Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        IUser? user = null;
        if (provider is IAuthenticationUserResolver userResolver)
        {
            user = await ResolveTenantConsistentUserAsync(
                () => userResolver.FindUserAsync(assertion, context, _userRepository, cancellationToken));
        }

        if (user == null && context.UserId.HasValue)
        {
            user = await ResolveTenantConsistentUserAsync(
                () => _userRepository.GetUserByIdAsync(context.UserId.Value, cancellationToken));
        }

        var userId = user?.Id ?? Guid.NewGuid();

        var (unprotectedCredential, credential, unprotectFailed) = await ResolveCredentialCoreAsync(userId, assertion, provider, context, cancellationToken);
        return (user, unprotectedCredential, credential, unprotectFailed);

        async Task<IUser?> ResolveTenantConsistentUserAsync(Func<Task<IUser?>> resolveUserAsync)
        {
            var resolvedUser = await resolveUserAsync();
            return resolvedUser != null && UserTenantOwnership.Matches(resolvedUser, context.TenantId)
                ? resolvedUser
                : null;
        }
    }

    public async Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);

        var (unprotectedCredential, credential, unprotectFailed) = await ResolveCredentialCoreAsync(userId, assertion, provider, null, cancellationToken);
        return (user, unprotectedCredential, credential, unprotectFailed);
    }

    private async Task<(UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveCredentialCoreAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        AuthenticationContext? context,
        CancellationToken cancellationToken)
    {
        UserCredential? credential;
        if (provider is IAuthenticationCredentialResolver credentialResolver)
        {
            credential = await credentialResolver.ResolveCredentialAsync(userId, assertion, context, _credentialRepository, cancellationToken);
            if (credential == null)
            {
                // Timing attack resistance: hit the repository even if no credential was resolved by the provider.
                credential = await _credentialRepository.GetCredentialForUserAsync(userId, provider.Key.Type, provider.Key.Name, Guid.NewGuid().ToString("N"), cancellationToken);
            }
        }
        else
        {
            var providerKey = provider.GetProviderKey(assertion, userId);
            if (string.IsNullOrEmpty(providerKey))
            {
                providerKey = Guid.NewGuid().ToString("N");
            }

            credential = await _credentialRepository.GetCredentialForUserAsync(userId, provider.Key.Type, provider.Key.Name, providerKey, cancellationToken);
        }

        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);
        return (unprotectedCredential, credential, unprotectFailed);
    }

    private (UserCredential? Credential, bool UnprotectFailed) UnprotectCredential(UserCredential? credential, IAuthenticationProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var now = _timeProvider.GetUtcNow();

        if (credential == null)
        {
            if (provider.ProtectsCredentials)
            {
                var dummyProtectedValue = _dummyValues.GetOrAdd(provider.TypicalCredentialLength, len => _secretProtector.Protect(new string('D', len)));
                try
                {
                    _secretProtector.Unprotect(dummyProtectedValue);
                }
                catch (System.Security.Cryptography.CryptographicException ex)
                {
                    DummyCredentialUnprotectFailed(
                        _logger,
                        provider.Key.Type.StorageValue,
                        provider.Key.Name,
                        provider.TypicalCredentialLength,
                        ex);
                    // Swallowing exception for timing resistance.
                }
            }

            return (null, false);
        }

        if (!provider.ProtectsCredentials)
        {
            if (!credential.IsAvailable(now))
            {
                return (null, false);
            }
            return (credential, false);
        }

        string? unprotectedValue = null;
        bool unprotectFailed = false;

        try
        {
            if (credential.CredentialValue != null)
            {
                unprotectedValue = _secretProtector.Unprotect(credential.CredentialValue);
            }
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            CredentialUnprotectFailed(
                _logger,
                credential.UserId,
                credential.Id,
                credential.ProviderType.StorageValue,
                credential.ProviderName,
                ex);
            unprotectFailed = true;
        }

        if (!credential.IsAvailable(now))
        {
            return (null, false);
        }

        var unprotectedCredential = credential.Clone();
        unprotectedCredential.CredentialValue = unprotectFailed ? null : unprotectedValue;

        return (unprotectedCredential, unprotectFailed);
    }

    public async Task<CredentialUsageUpdateResult> UpdateCredentialUsageAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(unprotectedCredential);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(provider);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        CredentialUsageUpdateResult updated;
        if (result.IsCredentialConsumed)
        {
            updated = await ConsumeAndRecordAsync(unprotectedCredential, originalCredential, cancellationToken);
        }
        else
        {
            updated = await PerformUpdateAsync(unprotectedCredential, originalCredential, result, provider, transaction, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

        return updated;
    }

    private async Task<CredentialUsageUpdateResult> PerformUpdateAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        IAshlarTransaction transaction,
        CancellationToken cancellationToken)
    {
        var metadataChanged = result.NewMetadata != null && result.NewMetadata != unprotectedCredential.Metadata;
        bool needsUpdate = PrepareMetadataAndUsage(unprotectedCredential, result);

        var valueUpdateRequested = result is { Status: AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: not null };
        var (protectionSucceeded, valueRequestedUpdate) = PrepareCredentialValue(unprotectedCredential, originalCredential, result, provider);
        needsUpdate |= valueRequestedUpdate;
        var providerRequestedUpdateAttempted = metadataChanged || valueUpdateRequested;
        var providerRequestedUpdateCanPersist = (metadataChanged || valueRequestedUpdate) && protectionSucceeded;

        if (!protectionSucceeded && !HandleProtectionFailure(unprotectedCredential, originalCredential, result, ref needsUpdate))
        {
            CredentialProtectionFailedRequired(
                _logger,
                unprotectedCredential.UserId,
                unprotectedCredential.Id,
                unprotectedCredential.ProviderType.StorageValue,
                unprotectedCredential.ProviderName,
                null);
            await RecordCredentialUpdateFailedAsync(unprotectedCredential, "protect_failed", cancellationToken);
            return CredentialUsageUpdateResult.RequiredFailed;
        }

        if (needsUpdate && IsWipeRisk(unprotectedCredential, originalCredential, provider))
        {
            CredentialUpdateWipeRisk(
                _logger,
                unprotectedCredential.UserId,
                unprotectedCredential.Id,
                unprotectedCredential.ProviderType.StorageValue,
                unprotectedCredential.ProviderName,
                null);
            await RecordCredentialUpdateFailedAsync(unprotectedCredential, "wipe_risk", cancellationToken);
            return result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required
                ? CredentialUsageUpdateResult.RequiredFailed
                : CredentialUsageUpdateResult.BestEffortFailed;
        }

        if (needsUpdate)
        {
            unprotectedCredential.UpdatedAt = _timeProvider.GetUtcNow();
        }

        if (!needsUpdate)
        {
            return CredentialUsageUpdateResult.NotNeeded;
        }

        return await PersistAndRecordUpdateAsync(
            unprotectedCredential,
            originalCredential,
            result,
            providerRequestedUpdateAttempted,
            providerRequestedUpdateCanPersist,
            cancellationToken);
    }

    private async Task<CredentialUsageUpdateResult> ConsumeAndRecordAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        CancellationToken cancellationToken)
    {
        var consumed = await _credentialRepository.ConsumeCredentialAsync(unprotectedCredential.Id, GetExpectedVersion(unprotectedCredential, originalCredential), cancellationToken);
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.CredentialConsumed,
            Outcome = consumed ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            UserId = unprotectedCredential.UserId,
            Provider = new AuthenticationProviderKey(unprotectedCredential.ProviderType, unprotectedCredential.ProviderName),
            FailureReason = consumed ? null : SecurityEventFailureReasons.CredentialUpdateFailed,
            Properties = new Dictionary<string, string>
            {
                [CredentialIdPropertyName] = unprotectedCredential.Id.ToString(),
                ["operation"] = "consume"
            }
        }, cancellationToken);
        return consumed ? CredentialUsageUpdateResult.NotNeeded : CredentialUsageUpdateResult.RequiredFailed;
    }

    private async Task<CredentialUsageUpdateResult> PersistAndRecordUpdateAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        bool providerRequestedUpdateAttempted,
        bool providerRequestedUpdateCanPersist,
        CancellationToken cancellationToken)
    {
        var (succeeded, persisted) = await PersistUpdateAsync(unprotectedCredential, originalCredential, result, cancellationToken);
        var providerUpdatePersisted = persisted && providerRequestedUpdateCanPersist;
        if (providerRequestedUpdateAttempted)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = providerUpdatePersisted ? AshlarSecurityEventTypes.CredentialUpdatePersisted : AshlarSecurityEventTypes.CredentialUpdateFailed,
                Outcome = providerUpdatePersisted ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
                UserId = unprotectedCredential.UserId,
                Provider = new AuthenticationProviderKey(unprotectedCredential.ProviderType, unprotectedCredential.ProviderName),
                FailureReason = providerUpdatePersisted ? null : SecurityEventFailureReasons.CredentialUpdateFailed,
                Properties = new Dictionary<string, string>
                {
                    [CredentialIdPropertyName] = unprotectedCredential.Id.ToString(),
                    ["operation"] = "update",
                    ["required"] = (result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required).ToString()
                }
            }, cancellationToken);
        }

        return new CredentialUsageUpdateResult(succeeded, providerUpdatePersisted);
    }

    private bool PrepareMetadataAndUsage(UserCredential credential, AuthenticationResult result)
    {
        var needsUpdate = false;
        var now = _timeProvider.GetUtcNow();

        if (result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required
            || !credential.LastUsedAt.HasValue
            || (now - credential.LastUsedAt.Value) >= _options.LastUsedAtUpdateThreshold)
        {
            credential.LastUsedAt = now;
            needsUpdate = true;
        }

        if (result.NewMetadata != null && result.NewMetadata != credential.Metadata)
        {
            credential.Metadata = result.NewMetadata;
            needsUpdate = true;
        }

        return needsUpdate;
    }

    private (bool Succeeded, bool NeedsUpdate) PrepareCredentialValue(
        UserCredential credential,
        UserCredential? original,
        AuthenticationResult result,
        IAuthenticationProvider provider)
    {
        if (result is { Status: AuthenticationResultStatus.SucceededWithCredentialUpdate, NewCredentialValue: not null })
        {
            var succeeded = TryProtectValue(credential, result.NewCredentialValue, provider);
            return (succeeded, succeeded);
        }

        if (original != null)
        {
            credential.CredentialValue = original.CredentialValue;
            return (true, false);
        }

        if (provider.ProtectsCredentials && credential.CredentialValue != null)
        {
            var succeeded = TryProtectValue(credential, credential.CredentialValue, provider);
            return (succeeded, false);
        }

        return (true, false);
    }

    private bool TryProtectValue(UserCredential credential, string value, IAuthenticationProvider provider)
    {
        try
        {
            credential.CredentialValue = provider.ProtectsCredentials
                ? _secretProtector.Protect(value)
                : value;
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            CredentialProtectionFailed(
                _logger,
                credential.UserId,
                credential.Id,
                credential.ProviderType.StorageValue,
                credential.ProviderName,
                ex);
            return false;
        }
    }

    private static bool HandleProtectionFailure(
        UserCredential credential,
        UserCredential? original,
        AuthenticationResult result,
        ref bool needsUpdate)
    {
        if (original != null)
        {
            credential.CredentialValue = original.CredentialValue;
        }
        else
        {
            credential.CredentialValue = null;
            needsUpdate = false;
        }

        return result.CredentialUpdateRequirement != CredentialUpdateRequirement.Required;
    }

    private static bool IsWipeRisk(UserCredential credential, UserCredential? original, IAuthenticationProvider provider)
    {
        return provider.ProtectsCredentials && credential.CredentialValue == null && original == null;
    }

    private async Task<(bool Succeeded, bool Persisted)> PersistUpdateAsync(
        UserCredential credential,
        UserCredential? original,
        AuthenticationResult result,
        CancellationToken cancellationToken)
    {
        try
        {
            var updateSucceeded = await _credentialRepository.UpdateCredentialAsync(credential, GetExpectedVersion(credential, original), cancellationToken);
            if (!updateSucceeded)
            {
                CredentialUpdateConcurrencyConflict(
                    _logger,
                    credential.UserId,
                    credential.Id,
                    credential.ProviderType.StorageValue,
                    credential.ProviderName,
                    null);
                return (result.CredentialUpdateRequirement != CredentialUpdateRequirement.Required, false);
            }

            return (true, true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            CredentialUpdatePersistenceFailed(
                _logger,
                credential.UserId,
                credential.Id,
                credential.ProviderType.StorageValue,
                credential.ProviderName,
                ex);
            return (result.CredentialUpdateRequirement != CredentialUpdateRequirement.Required, false);
        }
    }

    private static string GetExpectedVersion(UserCredential unprotectedCredential, UserCredential? originalCredential)
    {
        return originalCredential?.Version ?? unprotectedCredential.Version;
    }

    public async Task<Result> LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, string? credentialValue = null, string? credentialMetadata = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        var providerKeyIdentity = provider.Key;
        var providerName = providerKeyIdentity.Name;

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = providerKeyIdentity,
                FailureReason = AshlarFailureCodes.UserNotFound.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.UserNotFound);
        }

        var providerKey = provider.GetProviderKey(assertion, userId);
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = providerKeyIdentity,
                FailureReason = AshlarFailureCodes.InvalidProviderKey.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.InvalidProviderKey);
        }

        var linkedUser = await _userRepository.GetUserByProviderKeyAsync(providerKeyIdentity.Type, providerName, providerKey, cancellationToken);

        if (linkedUser != null)
        {
            var code = linkedUser.Id != userId ? AshlarFailureCodes.AlreadyLinkedToOther : AshlarFailureCodes.AlreadyLinkedToSelf;
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = providerKeyIdentity,
                FailureReason = code.Value
            }, cancellationToken);
            return Result.Failure(code);
        }

        credentialValue = provider.PrepareCredentialValue(assertion, credentialValue);

        if (provider.ProtectsCredentials && credentialValue != null)
        {
            credentialValue = _secretProtector.Protect(credentialValue);
        }

        var credential = new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = providerKeyIdentity.Type,
            ProviderName = providerName,
            ProviderKey = providerKey,
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = _timeProvider.GetUtcNow(),
            UpdatedAt = null,
            ExpiresAt = null,
            RevokedAt = null,
            Status = CredentialStatus.Active,
            Metadata = credentialMetadata,
            CredentialValue = credentialValue
        };

        try
        {
            await _credentialRepository.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        }
        catch (CredentialProviderKeyConflictException)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = providerKeyIdentity,
                FailureReason = AshlarFailureCodes.AlreadyLinkedToOther.Value
            }, cancellationToken);
            return Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther);
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.CredentialLinked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            Provider = providerKeyIdentity,
            Properties = new Dictionary<string, string>
            {
                [CredentialIdPropertyName] = credential.Id.ToString()
            }
        }, cancellationToken);

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    private Task RecordCredentialUpdateFailedAsync(UserCredential credential, string reason, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.CredentialUpdateFailed,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = credential.UserId,
            Provider = new AuthenticationProviderKey(credential.ProviderType, credential.ProviderName),
            FailureReason = SecurityEventFailureReasons.CredentialUpdateFailed,
            Properties = new Dictionary<string, string>
            {
                [CredentialIdPropertyName] = credential.Id.ToString(),
                ["reason"] = reason
            }
        }, cancellationToken);
    }
}

internal sealed record CredentialServiceDependencies(
    IdentityServiceOptions? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    ILogger<CredentialService>? Logger = null);
