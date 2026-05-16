using System.Collections.Concurrent;
using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Security.Encryption;

namespace Ashlar.Identity;

/// <summary>
/// Implements credential management services including resolution, linking, and lifecycle updates.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="secretProtector">The secret protector value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
/// <param name="options">The options value.</param>
/// <param name="timeProvider">The time provider value.</param>
/// <param name="securityEventSink">The security event sink value.</param>
/// <remarks>
/// This service implements timing attack resistance by ensuring that unprotection operations
/// are performed even when a user or credential is not found, using provider-specific dummy values.
/// </remarks>
public sealed class CredentialService(
    IIdentityRepository repository,
    ISecretProtector secretProtector,
    IAshlarTransactionProvider transactionProvider,
    IdentityServiceOptions? options = null,
    TimeProvider? timeProvider = null,
    ISecurityEventSink? securityEventSink = null)
    : ICredentialService
{
    private const string CredentialIdPropertyName = "credential_id";
    private readonly IIdentityRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly ISecretProtector _secretProtector = secretProtector ?? throw new ArgumentNullException(nameof(secretProtector));
    private readonly IAshlarTransactionProvider _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
    private readonly IdentityServiceOptions _options = options ?? new IdentityServiceOptions();
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private readonly SecurityEventEmitter _securityEvents = new(securityEventSink, timeProvider ?? TimeProvider.System);
    private readonly ConcurrentDictionary<int, string> _dummyValues = new();
    /// <inheritdoc />
    public async Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        var user = await provider.FindUserAsync(assertion, context, _repository, cancellationToken);

        if (user == null && context.UserId.HasValue)
        {
            user = await _repository.GetUserByIdAsync(context.UserId.Value, cancellationToken);
        }

        var userId = user?.Id ?? Guid.NewGuid();

        var (unprotectedCredential, credential, unprotectFailed) = await ResolveCredentialCoreAsync(userId, assertion, provider, cancellationToken);
        return (user, unprotectedCredential, credential, unprotectFailed);
    }
    /// <inheritdoc />
    public async Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);

        var (unprotectedCredential, credential, unprotectFailed) = await ResolveCredentialCoreAsync(userId, assertion, provider, cancellationToken);
        return (user, unprotectedCredential, credential, unprotectFailed);
    }

    private async Task<(UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveCredentialCoreAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken)
    {
        var providerKey = provider.GetProviderKey(assertion, userId);

        UserCredential? credential;
        if (!string.IsNullOrEmpty(providerKey))
        {
            credential = await _repository.GetCredentialForUserAsync(userId, provider.Key.Type, provider.Key.Name, providerKey, cancellationToken);
        }
        else
        {
            // Timing attack resistance: hit the repository even if no credential was resolved by the provider.
            credential = await provider.ResolveCredentialAsync(userId, assertion, _repository, cancellationToken) ?? await _repository.GetCredentialForUserAsync(userId, provider.Key.Type, provider.Key.Name, Guid.NewGuid().ToString("N"), cancellationToken);
        }

        var (unprotectedCredential, unprotectFailed) = UnprotectCredential(credential, provider);
        return (unprotectedCredential, credential, unprotectFailed);
    }

    /// <summary>
    /// Unprotects the credential value if the provider requires protection.
    /// </summary>
    /// <param name="provider">The provider value.</param>
    /// <remarks>
    /// This method is timing-safe. If the <paramref name="credential"/> is <see langword="null" />, it performs an unprotection
    /// operation on a cached dummy value matching the provider's typical credential length.
    /// </remarks>
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
                catch (System.Security.Cryptography.CryptographicException)
                {
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
        catch (System.Security.Cryptography.CryptographicException)
        {
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

    /// <inheritdoc />
    public async Task<bool> UpdateCredentialUsageAsync(
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

        bool updated;
        if (result.IsCredentialConsumed)
        {
            updated = await ConsumeAndRecordAsync(unprotectedCredential, originalCredential, transaction, cancellationToken);
        }
        else
        {
            updated = await PerformUpdateAsync(unprotectedCredential, originalCredential, result, provider, transaction, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);

        return updated;
    }

    private async Task<bool> PerformUpdateAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        IAshlarTransaction transaction,
        CancellationToken cancellationToken)
    {
        bool needsUpdate = PrepareMetadataAndUsage(unprotectedCredential, result);

        var (protectionSucceeded, valueRequestedUpdate) = PrepareCredentialValue(unprotectedCredential, originalCredential, result, provider);
        needsUpdate |= valueRequestedUpdate;

        if (!protectionSucceeded && !HandleProtectionFailure(unprotectedCredential, originalCredential, result, ref needsUpdate))
        {
            transaction.OnCommitted(ct => RecordCredentialUpdateFailedAsync(unprotectedCredential, "protect_failed", ct));
            return false;
        }

        if (needsUpdate && IsWipeRisk(unprotectedCredential, originalCredential, provider))
        {
            transaction.OnCommitted(ct => RecordCredentialUpdateFailedAsync(unprotectedCredential, "wipe_risk", ct));
            return false;
        }

        if (needsUpdate)
        {
            unprotectedCredential.UpdatedAt = _timeProvider.GetUtcNow();
        }

        return !needsUpdate || await PersistAndRecordUpdateAsync(unprotectedCredential, originalCredential, result, transaction, cancellationToken);
    }

    private async Task<bool> ConsumeAndRecordAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        IAshlarTransaction transaction,
        CancellationToken cancellationToken)
    {
        var consumed = await _repository.ConsumeCredentialAsync(unprotectedCredential.Id, GetExpectedVersion(unprotectedCredential, originalCredential), cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
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
        }, ct));
        return consumed;
    }

    private async Task<bool> PersistAndRecordUpdateAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAshlarTransaction transaction,
        CancellationToken cancellationToken)
    {
        var (succeeded, persisted) = await PersistUpdateAsync(unprotectedCredential, originalCredential, result, cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = persisted ? AshlarSecurityEventTypes.CredentialUpdatePersisted : AshlarSecurityEventTypes.CredentialUpdateFailed,
            Outcome = persisted ? SecurityEventOutcomes.Success : SecurityEventOutcomes.Failure,
            UserId = unprotectedCredential.UserId,
            Provider = new AuthenticationProviderKey(unprotectedCredential.ProviderType, unprotectedCredential.ProviderName),
            FailureReason = persisted ? null : SecurityEventFailureReasons.CredentialUpdateFailed,
            Properties = new Dictionary<string, string>
            {
                [CredentialIdPropertyName] = unprotectedCredential.Id.ToString(),
                ["operation"] = "update",
                ["required"] = (result.CredentialUpdateRequirement == CredentialUpdateRequirement.Required).ToString()
            }
        }, ct));
        return succeeded;
    }

    private bool PrepareMetadataAndUsage(UserCredential credential, AuthenticationResult result)
    {
        var needsUpdate = false;
        var now = _timeProvider.GetUtcNow();

        if (!credential.LastUsedAt.HasValue || (now - credential.LastUsedAt.Value) >= _options.LastUsedAtUpdateThreshold)
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

        // TODO: Log exception.
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
            var updateSucceeded = await _repository.UpdateCredentialAsync(credential, GetExpectedVersion(credential, original), cancellationToken);
            if (!updateSucceeded)
            {
                // TODO: Log concurrency conflict.
                return (result.CredentialUpdateRequirement != CredentialUpdateRequirement.Required, false);
            }

            return (true, true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // TODO: Log exception.
            return (result.CredentialUpdateRequirement != CredentialUpdateRequirement.Required, false);
        }
    }

    private static string GetExpectedVersion(UserCredential unprotectedCredential, UserCredential? originalCredential)
    {
        return originalCredential?.Version ?? unprotectedCredential.Version;
    }

    /// <inheritdoc />
    public async Task<Result> LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, string? credentialValue = null, string? initialMetadata = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(provider);

        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));

        var providerKeyIdentity = provider.Key;
        var providerName = providerKeyIdentity.Name;

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var user = await _repository.GetUserByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = providerKeyIdentity,
                FailureReason = "user_not_found"
            }, cancellationToken);
            return Result.Failure("user_not_found");
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
                FailureReason = "invalid_provider_key"
            }, cancellationToken);
            return Result.Failure("invalid_provider_key");
        }

        var linkedUser = await _repository.GetUserByProviderKeyAsync(providerKeyIdentity.Type, providerName, providerKey, cancellationToken);

        if (linkedUser != null)
        {
            var reason = linkedUser.Id != userId ? "already_linked_to_other" : "already_linked_to_self";
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.CredentialLinked,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = userId,
                Provider = providerKeyIdentity,
                FailureReason = reason
            }, cancellationToken);
            return Result.Failure(reason);
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
            Metadata = initialMetadata,
            CredentialValue = credentialValue
        };

        await _repository.CreateOrReplaceCredentialAsync(credential, cancellationToken);
        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.CredentialLinked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = userId,
            Provider = providerKeyIdentity,
            Properties = new Dictionary<string, string>
            {
                [CredentialIdPropertyName] = credential.Id.ToString()
            }
        }, ct));

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
