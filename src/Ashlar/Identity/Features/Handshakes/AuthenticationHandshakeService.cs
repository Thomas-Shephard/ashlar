using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.Handshakes;

/// <summary>
/// Creates and verifies short-lived authentication handshakes for MFA and step-up flows.
/// </summary>
internal sealed class AuthenticationHandshakeService : IAuthenticationHandshakeService, IAuthenticationHandshakeCompletionService
{
    private const string HandshakeIdProperty = "handshake_id";
    private const string LookupRateLimitPurpose = "handshake-lookup";
    private const string VerificationRateLimitPurpose = "handshake-verify";
    private const int MaxMetadataEntries = 20;
    private const int MaxMetadataKeyLength = 128;
    private const int MaxMetadataValueLength = 512;

    private readonly IAuthenticationHandshakeRepository _repository;
    private readonly ISecureTokenGenerator _tokenGenerator;
    private readonly ISecureTokenHasher _tokenHasher;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly AuthenticationHandshakeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly AuthenticationRateLimitChecker? _rateLimitChecker;
    private readonly IUserRepository? _userRepository;
    private readonly SecurityNotificationEmitter _notifications;

    private enum HandshakeRateLimitMode
    {
        None,
        LookupOnly,
        LookupAndVerification
    }

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="repository">Handshake repository that stores token hashes and handshake state.</param>
    /// <param name="tokenGenerator">Generator used to issue raw handshake tokens.</param>
    /// <param name="tokenHasher">Hasher used before looking up or persisting handshake tokens.</param>
    /// <param name="transactionProvider">Transaction provider used for handshake mutations.</param>
    /// <param name="dependencies">Handshake options, rate limiting, audit, user lookup, and notification dependencies.</param>
    public AuthenticationHandshakeService(
        IAuthenticationHandshakeRepository repository,
        ISecureTokenGenerator tokenGenerator,
        ISecureTokenHasher tokenHasher,
        IAshlarTransactionProvider transactionProvider,
        AuthenticationHandshakeServiceDependencies? dependencies = null)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _tokenGenerator = tokenGenerator ?? throw new ArgumentNullException(nameof(tokenGenerator));
        _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _options = dependencies?.Options?.Value ?? new AuthenticationHandshakeOptions();
        _timeProvider = dependencies?.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(dependencies?.SecurityEventSink, _timeProvider);
        _rateLimitChecker = dependencies?.RateLimiter == null ? null : new AuthenticationRateLimitChecker(dependencies.RateLimiter);
        _userRepository = dependencies?.UserRepository;
        _notifications = new SecurityNotificationEmitter(dependencies?.NotificationService);
    }

    public async Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(
        CreateAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.UserId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(request));
        }
        ArgumentNullException.ThrowIfNull(request.RequiredFactors);

        var requiredFactors = request.RequiredFactors.ToHashSet();
        if (requiredFactors.Count == 0)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.NoFactorsSpecified.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshakeCreated>(AshlarFailureCodes.NoFactorsSpecified);
        }

        try
        {
            ValidateMetadata(request.Metadata, nameof(request));
        }
        catch (ArgumentException)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = request.UserId,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.InvalidMetadata.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshakeCreated>(AshlarFailureCodes.InvalidMetadata);
        }

        var metadata = NormalizeMetadata(request.Metadata);

        var token = _tokenGenerator.GenerateToken();
        var tokenHash = _tokenHasher.HashToken(token);
        var now = _timeProvider.GetUtcNow();

        var handshake = new AuthenticationHandshake(
            Guid.NewGuid(),
            request.UserId,
            tokenHash,
            now,
            now.Add(_options.Expiry),
            false,
            false,
            requiredFactors,
            new HashSet<string>(),
            metadata)
        {
            TenantId = request.Context?.TenantId
        };

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        await _repository.CreateAsync(handshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Context = request.Context,
            Properties = new Dictionary<string, string>
            {
                [HandshakeIdProperty] = handshake.Id.ToString(),
                ["required_factors"] = string.Join(",", handshake.RequiredFactors)
            }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return Result<AuthenticationHandshakeCreated>.Success(new AuthenticationHandshakeCreated(ToCreatedHandshake(handshake), token));
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationHandshake>> BeginFactorChallengeAsync(
        VerifyAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        var result = await LoadHandshakeForFactorVerificationAsync(request, HandshakeRateLimitMode.LookupOnly, cancellationToken);
        return result;
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationHandshake>> BeginFactorVerificationAsync(
        VerifyAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        var result = await LoadHandshakeForFactorVerificationAsync(request, HandshakeRateLimitMode.LookupAndVerification, cancellationToken);
        return result;
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticationHandshake>> BeginVerificationAsync(
        BeginAuthenticationHandshakeVerificationRequest request,
        CancellationToken cancellationToken = default)
    {
        var result = await LoadHandshakeForVerificationAsync(request, HandshakeRateLimitMode.LookupAndVerification, cancellationToken);
        return result;
    }

    public async Task<Result<AuthenticationHandshake>> CompleteFactorVerificationAsync(
        VerifyAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var result = await LoadHandshakeForFactorVerificationAsync(request, HandshakeRateLimitMode.None, cancellationToken);
        if (!result.Succeeded)
        {
            return result;
        }

        var handshake = result.Value!;
        var now = _timeProvider.GetUtcNow();
        var verifiedFactors = handshake.VerifiedFactors.ToHashSet();
        var factorType = ResolveRequiredFactor(handshake, request.FactorType);
        verifiedFactors.Add(factorType);

        var isCompleted = handshake.RequiredFactors.All(requiredFactor =>
            verifiedFactors.Any(verifiedFactor => AuthenticationFactorTypes.Matches(requiredFactor, verifiedFactor)));
        try
        {
            ValidateMetadata(request.Metadata, nameof(request));
        }
        catch (ArgumentException)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.InvalidMetadata, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.InvalidMetadata);
        }

        var updatedHandshake = handshake with
        {
            VerifiedFactors = verifiedFactors,
            IsCompleted = isCompleted,
            CompletedAt = isCompleted ? now : handshake.CompletedAt,
            Metadata = MergeMetadata(handshake.Metadata, request.Metadata)
        };

        if (!await TryUpdateHandshakeAsync(handshake, updatedHandshake, request.Context, cancellationToken))
        {
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.ConcurrencyConflict);
        }

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = isCompleted ? AshlarSecurityEventTypes.AuthenticationHandshakeCompleted : AshlarSecurityEventTypes.AuthenticationHandshakeFactorVerified,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Context = request.Context,
            Properties = new Dictionary<string, string>
            {
                [HandshakeIdProperty] = handshake.Id.ToString(),
                ["verified_factor"] = factorType,
                ["is_completed"] = isCompleted.ToString()
            }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return Result.Success(updatedHandshake);
    }

    private async Task<Result<AuthenticationHandshake>> LoadHandshakeForFactorVerificationAsync(
        VerifyAuthenticationHandshakeRequest request,
        HandshakeRateLimitMode rateLimitMode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var result = await LoadHandshakeForVerificationAsync(
            new BeginAuthenticationHandshakeVerificationRequest(request.HandshakeToken, request.Context),
            rateLimitMode,
            cancellationToken);
        if (!result.Succeeded || result.Value == null)
        {
            return result;
        }

        var handshake = result.Value;
        var factorType = ResolveRequiredFactor(handshake, request.FactorType);
        if (factorType.Length == 0)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.InvalidFactorType, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.InvalidFactorType);
        }

        if (handshake.VerifiedFactors.Any(verifiedFactor => AuthenticationFactorTypes.Matches(verifiedFactor, factorType)))
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.FactorAlreadyVerified, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.FactorAlreadyVerified);
        }

        return Result.Success(handshake);
    }

    private static CreatedAuthenticationHandshake ToCreatedHandshake(AuthenticationHandshake handshake)
    {
        return new CreatedAuthenticationHandshake(
            handshake.Id,
            handshake.UserId,
            handshake.TenantId,
            handshake.CreatedAt,
            handshake.ExpiresAt,
            handshake.RequiredFactors,
            handshake.Metadata);
    }

    private async Task<Result<AuthenticationHandshake>> LoadHandshakeForVerificationAsync(
        BeginAuthenticationHandshakeVerificationRequest request,
        HandshakeRateLimitMode rateLimitMode,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (rateLimitMode != HandshakeRateLimitMode.None)
        {
            var lookupRateLimitResult = await CheckLookupRateLimitAsync(request.Context, cancellationToken);
            if (lookupRateLimitResult != null)
            {
                return lookupRateLimitResult;
            }
        }

        if (!SecureTokenHashing.TryHashToken(_tokenHasher, request.HandshakeToken, out var tokenHash))
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.HandshakeNotFound.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound);
        }

        var handshake = await _repository.FindByTokenHashAsync(tokenHash, forUpdate: rateLimitMode == HandshakeRateLimitMode.None, cancellationToken);
        if (handshake == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                Context = request.Context,
                FailureReason = AshlarFailureCodes.HandshakeNotFound.Value
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound);
        }

        if (!TenantMatches(handshake, request.Context))
        {
            await RecordHandshakeTenantMismatchAsync(request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound);
        }

        if (rateLimitMode == HandshakeRateLimitMode.LookupAndVerification)
        {
            var rateLimitResult = await CheckRateLimitAsync(handshake, request.Context, cancellationToken);
            if (rateLimitResult != null)
            {
                return rateLimitResult;
            }
        }

        var now = _timeProvider.GetUtcNow();
        if (handshake.IsRevoked)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.HandshakeRevoked, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeRevoked);
        }

        if (handshake.IsCompleted)
        {
            await RecordHandshakeFailedAsync(handshake, AshlarFailureCodes.HandshakeAlreadyCompleted, request.Context, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeAlreadyCompleted);
        }

        if (handshake.ExpiresAt <= now)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeExpired,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = handshake.UserId,
                Context = request.Context,
                Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
            }, cancellationToken);
            return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeExpired);
        }

        return Result.Success(handshake);
    }

    /// <summary>
    /// Revokes an in-progress handshake by raw token.
    /// </summary>
    /// <param name="handshakeToken">Raw handshake token presented by the caller. Do not log or persist this value.</param>
    /// <param name="context">Authentication request context used for audit and notifications.</param>
    /// <param name="cancellationToken">A token that can cancel revocation.</param>
    /// <returns>A result indicating whether revocation succeeded or the handshake was not found.</returns>
    public async Task<Result> RevokeHandshakeAsync(string? handshakeToken, AuthenticationContext? context = null, CancellationToken cancellationToken = default)
    {
        if (!SecureTokenHashing.TryHashToken(_tokenHasher, handshakeToken, out var tokenHash))
        {
            return Result.Failure(AshlarFailureCodes.HandshakeNotFound);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var handshake = await _repository.FindByTokenHashAsync(tokenHash, forUpdate: true, cancellationToken: cancellationToken);
        if (handshake == null) return Result.Failure(AshlarFailureCodes.HandshakeNotFound);
        if (!TenantMatches(handshake, context))
        {
            await RecordHandshakeTenantMismatchAsync(context, cancellationToken);
            return Result.Failure(AshlarFailureCodes.HandshakeNotFound);
        }

        if (handshake.IsRevoked) return Result.Success();

        var updatedHandshake = handshake with { IsRevoked = true, RevokedAt = _timeProvider.GetUtcNow() };

        if (!await TryUpdateHandshakeAsync(handshake, updatedHandshake, context, cancellationToken))
        {
            return Result.Failure(AshlarFailureCodes.ConcurrencyConflict);
        }

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Context = context,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success();
    }

    private async Task<bool> TryUpdateHandshakeAsync(
        AuthenticationHandshake originalHandshake,
        AuthenticationHandshake updatedHandshake,
        AuthenticationContext? context,
        CancellationToken cancellationToken)
    {
        var updated = await _repository.UpdateAsync(updatedHandshake, cancellationToken);
        if (updated)
        {
            return true;
        }

        await RecordHandshakeFailedAsync(originalHandshake, AshlarFailureCodes.ConcurrencyConflict, context, cancellationToken);
        return false;
    }

    private Task RecordHandshakeFailedAsync(AuthenticationHandshake handshake, AshlarFailureCode reason, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = handshake.UserId,
            Context = context,
            FailureReason = reason.Value,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, cancellationToken);
    }

    private Task RecordHandshakeTenantMismatchAsync(AuthenticationContext? context, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
            Outcome = SecurityEventOutcomes.Failure,
            Context = context,
            FailureReason = AshlarFailureCodes.HandshakeNotFound.Value
        }, cancellationToken);
    }

    private static bool TenantMatches(AuthenticationHandshake handshake, AuthenticationContext? context)
    {
        return handshake.TenantId == context?.TenantId;
    }

    private async Task<Result<AuthenticationHandshake>?> CheckRateLimitAsync(AuthenticationHandshake handshake, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        if (_rateLimitChecker == null)
        {
            return null;
        }

        var userBucket = AuthenticationRateLimitDimensions.User(handshake.UserId);
        var sourceBucket = AuthenticationRateLimitDimensions.Source(context);
        var checks = new[]
        {
            CreateHandshakeVerificationRateLimitCheck(handshake, context, "source", sourceBucket),
            CreateHandshakeVerificationRateLimitCheck(handshake, context, "user", userBucket)
        };

        foreach (var check in checks)
        {
            var rateLimitDecision = await _rateLimitChecker.CheckAsync(check, cancellationToken);
            if (!rateLimitDecision.IsAllowed)
            {
                await RecordVerificationRateLimitedAsync(handshake, context, cancellationToken);
                return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.RateLimitExceeded);
            }
        }

        return null;
    }

    private async Task<Result<AuthenticationHandshake>?> CheckLookupRateLimitAsync(AuthenticationContext? context, CancellationToken cancellationToken)
    {
        if (_rateLimitChecker == null)
        {
            return null;
        }

        var rateLimitDecision = await _rateLimitChecker.CheckAsync(new AuthenticationRateLimitCheck(
            LookupRateLimitPurpose,
            "source",
            AuthenticationRateLimitDimensions.Source(context),
            _options.VerificationRateLimit)
        {
            Context = context
        }, cancellationToken);

        if (rateLimitDecision.IsAllowed)
        {
            return null;
        }

        await RecordLookupRateLimitedAsync(context, cancellationToken);
        return Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.RateLimitExceeded);
    }

    private AuthenticationRateLimitCheck CreateHandshakeVerificationRateLimitCheck(
        AuthenticationHandshake handshake,
        AuthenticationContext? context,
        string dimensionName,
        string dimensionValue)
    {
        return new AuthenticationRateLimitCheck(VerificationRateLimitPurpose, dimensionName, dimensionValue, _options.VerificationRateLimit)
        {
            Context = context,
            UserId = handshake.UserId,
            TenantId = handshake.TenantId
        };
    }

    private async Task RecordLookupRateLimitedAsync(AuthenticationContext? context, CancellationToken cancellationToken)
    {
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeVerificationRateLimited,
            Outcome = SecurityEventOutcomes.Failure,
            Context = context,
            FailureReason = SecurityEventFailureReasons.RateLimited
        }, cancellationToken);
    }

    private async Task RecordVerificationRateLimitedAsync(AuthenticationHandshake handshake, AuthenticationContext? context, CancellationToken cancellationToken)
    {
        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeVerificationRateLimited,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = handshake.UserId,
            Context = context,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, cancellationToken);

        if (_userRepository != null)
        {
            var user = await _userRepository.GetUserByIdAsync(handshake.UserId, cancellationToken);
            if (user != null)
            {
                await _notifications.NotifyAsync(SecurityNotificationType.SuspiciousAuthenticationAttempt, user, _timeProvider.GetUtcNow(), cancellationToken: cancellationToken);
            }
        }
    }

    private static Dictionary<string, string>? MergeMetadata(
        IDictionary<string, string>? existingMetadata,
        IDictionary<string, string>? requestMetadata)
    {
        Dictionary<string, string>? updatedMetadata = NormalizeMetadata(existingMetadata);
        if (requestMetadata == null)
        {
            return updatedMetadata;
        }

        updatedMetadata ??= [];
        foreach (var kvp in requestMetadata)
        {
            updatedMetadata[kvp.Key] = NormalizeMetadataValue(kvp.Value);
        }

        return updatedMetadata;
    }

    private static Dictionary<string, string>? NormalizeMetadata(IDictionary<string, string>? metadata)
    {
        if (metadata == null)
        {
            return null;
        }

        var normalized = new Dictionary<string, string>(metadata.Count, StringComparer.Ordinal);
        foreach (var kvp in metadata)
        {
            normalized[kvp.Key] = NormalizeMetadataValue(kvp.Value);
        }

        return normalized;
    }

    private static void ValidateMetadata(IDictionary<string, string>? metadata, string paramName)
    {
        if (metadata == null)
        {
            return;
        }

        if (metadata.Count > MaxMetadataEntries)
        {
            throw new ArgumentException($"Metadata cannot contain more than {MaxMetadataEntries} entries.", paramName);
        }

        foreach (var kvp in metadata)
        {
            if (string.IsNullOrWhiteSpace(kvp.Key))
            {
                throw new ArgumentException("Metadata keys cannot be null or whitespace.", paramName);
            }

            if (kvp.Key.Length > MaxMetadataKeyLength)
            {
                throw new ArgumentException($"Metadata keys cannot exceed {MaxMetadataKeyLength} characters.", paramName);
            }

            if (GetMetadataValueLength(kvp.Value) > MaxMetadataValueLength)
            {
                throw new ArgumentException($"Metadata values cannot exceed {MaxMetadataValueLength} characters.", paramName);
            }
        }
    }

    private static string NormalizeMetadataValue(string? value) => value ?? string.Empty;

    private static int GetMetadataValueLength(string? value) => value?.Length ?? 0;

    private static string ResolveRequiredFactor(AuthenticationHandshake handshake, string factorType)
    {
        return handshake.RequiredFactors.FirstOrDefault(requiredFactor => AuthenticationFactorTypes.Matches(requiredFactor, factorType)) ?? string.Empty;
    }
}

/// <summary>
/// Groups optional dependencies used by the authentication handshake service.
/// </summary>
/// <param name="Options">Handshake lifetime and verification rate-limit options.</param>
/// <param name="TimeProvider">Clock used for timestamps and expiration checks.</param>
/// <param name="SecurityEventSink">Optional sink used to record handshake security events.</param>
/// <param name="RateLimiter">Optional rate limiter used for handshake lookup and verification attempts.</param>
/// <param name="UserRepository">Looks up users when operations need notification context.</param>
/// <param name="NotificationService">Optional service used to send handshake-related security notifications.</param>
public sealed record AuthenticationHandshakeServiceDependencies(
    IOptions<AuthenticationHandshakeOptions>? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    IAuthenticationRateLimiter? RateLimiter = null,
    IUserRepository? UserRepository = null,
    ISecurityNotificationService? NotificationService = null);
