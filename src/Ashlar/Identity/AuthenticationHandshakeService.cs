using Ashlar.Auditing;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity;

public sealed class AuthenticationHandshakeService : IAuthenticationHandshakeService
{
    private const string HandshakeIdProperty = "handshake_id";

    private readonly IAuthenticationHandshakeRepository _repository;
    private readonly ISecureTokenGenerator _tokenGenerator;
    private readonly ISecureTokenHasher _tokenHasher;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly AuthenticationHandshakeOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IAuthenticationRateLimiter? _rateLimiter;

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
        _rateLimiter = dependencies?.RateLimiter;
    }

    public async Task<(AuthenticationHandshake Handshake, string Token)> CreateHandshakeAsync(
        CreateAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.UserId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(request));
        ArgumentNullException.ThrowIfNull(request.RequiredFactors);

        var requiredFactors = request.RequiredFactors.ToHashSet();
        if (requiredFactors.Count == 0) throw new ArgumentException("At least one required factor must be specified.", nameof(request));

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
            request.Metadata);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        await _repository.CreateAsync(handshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeCreated,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Properties = new Dictionary<string, string>
            {
                [HandshakeIdProperty] = handshake.Id.ToString(),
                ["required_factors"] = string.Join(",", handshake.RequiredFactors)
            }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return (handshake, token);
    }

    public async Task<AuthenticationHandshakeResult> VerifyFactorAsync(
        VerifyAuthenticationHandshakeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.HandshakeToken)) return new AuthenticationHandshakeResult(false, ErrorMessage: "Token is required.");

        var tokenHash = _tokenHasher.HashToken(request.HandshakeToken);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var handshake = await _repository.FindByTokenHashAsync(tokenHash, forUpdate: true, cancellationToken);
        if (handshake == null)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
                Outcome = SecurityEventOutcomes.Failure,
                FailureReason = "handshake_not_found"
            }, cancellationToken);
            return new AuthenticationHandshakeResult(false, ErrorMessage: "Handshake not found.");
        }

        var rateLimitResult = await CheckRateLimitAsync(handshake, cancellationToken);
        if (rateLimitResult != null)
        {
            return rateLimitResult;
        }

        var now = _timeProvider.GetUtcNow();
        if (handshake.IsRevoked)
        {
            await RecordHandshakeFailedAsync(handshake, "handshake_revoked", cancellationToken);
            return new AuthenticationHandshakeResult(false, handshake, "Handshake is revoked.");
        }

        if (handshake.IsCompleted)
        {
            await RecordHandshakeFailedAsync(handshake, "handshake_already_completed", cancellationToken);
            return new AuthenticationHandshakeResult(false, handshake, "Handshake is already completed.");
        }

        if (handshake.ExpiresAt <= now)
        {
            await _securityEvents.RecordAsync(new SecurityEventDescriptor
            {
                EventType = AshlarSecurityEventTypes.AuthenticationHandshakeExpired,
                Outcome = SecurityEventOutcomes.Failure,
                UserId = handshake.UserId,
                Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
            }, cancellationToken);
            return new AuthenticationHandshakeResult(false, handshake, "Handshake expired.");
        }

        if (!handshake.RequiredFactors.Contains(request.FactorType))
        {
            await RecordHandshakeFailedAsync(handshake, "invalid_factor_type", cancellationToken);
            return new AuthenticationHandshakeResult(false, handshake, "Invalid factor type.");
        }

        if (handshake.VerifiedFactors.Contains(request.FactorType))
        {
            await RecordHandshakeFailedAsync(handshake, "factor_already_verified", cancellationToken);
            return new AuthenticationHandshakeResult(false, handshake, "Factor already verified.");
        }

        var verifiedFactors = handshake.VerifiedFactors.ToHashSet();
        verifiedFactors.Add(request.FactorType);

        var isCompleted = handshake.RequiredFactors.All(verifiedFactors.Contains);

        var updatedHandshake = handshake with
        {
            VerifiedFactors = verifiedFactors,
            IsCompleted = isCompleted,
            CompletedAt = isCompleted ? now : handshake.CompletedAt,
            Metadata = MergeMetadata(handshake.Metadata, request.Metadata)
        };

        await _repository.UpdateAsync(updatedHandshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = isCompleted ? AshlarSecurityEventTypes.AuthenticationHandshakeCompleted : AshlarSecurityEventTypes.AuthenticationHandshakeFactorVerified,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Properties = new Dictionary<string, string>
            {
                [HandshakeIdProperty] = handshake.Id.ToString(),
                ["verified_factor"] = request.FactorType,
                ["is_completed"] = isCompleted.ToString()
            }
        }, ct));

        await transaction.CommitAsync(cancellationToken);

        return new AuthenticationHandshakeResult(true, updatedHandshake);
    }

    public async Task<AuthenticationHandshake?> GetHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(handshakeToken)) return null;
        var tokenHash = _tokenHasher.HashToken(handshakeToken);
        return await _repository.FindByTokenHashAsync(tokenHash, cancellationToken: cancellationToken);
    }

    public async Task RevokeHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(handshakeToken)) return;
        var tokenHash = _tokenHasher.HashToken(handshakeToken);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);

        var handshake = await _repository.FindByTokenHashAsync(tokenHash, forUpdate: true, cancellationToken: cancellationToken);
        if (handshake == null || handshake.IsRevoked) return;

        var updatedHandshake = handshake with { IsRevoked = true, RevokedAt = _timeProvider.GetUtcNow() };

        await _repository.UpdateAsync(updatedHandshake, cancellationToken);

        transaction.OnCommitted(ct => _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeRevoked,
            Outcome = SecurityEventOutcomes.Success,
            UserId = handshake.UserId,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, ct));

        await transaction.CommitAsync(cancellationToken);
    }

    private Task RecordHandshakeFailedAsync(AuthenticationHandshake handshake, string reason, CancellationToken cancellationToken)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeFailed,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = handshake.UserId,
            FailureReason = reason,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, cancellationToken);
    }

    private async Task<AuthenticationHandshakeResult?> CheckRateLimitAsync(AuthenticationHandshake handshake, CancellationToken cancellationToken)
    {
        if (_rateLimiter == null)
        {
            return null;
        }

        var rateLimitDecision = await _rateLimiter.CheckAsync(new RateLimitAttempt
        {
            Key = $"handshake-verify:{handshake.UserId}",
            Purpose = "handshake-verify"
        }, _options.VerificationRateLimit, cancellationToken);

        if (rateLimitDecision.IsAllowed)
        {
            return null;
        }

        await _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = AshlarSecurityEventTypes.AuthenticationHandshakeVerificationRateLimited,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = handshake.UserId,
            Properties = new Dictionary<string, string> { [HandshakeIdProperty] = handshake.Id.ToString() }
        }, cancellationToken);
        return new AuthenticationHandshakeResult(false, ErrorMessage: "Rate limit exceeded.");
    }

    private static Dictionary<string, string>? MergeMetadata(
        IDictionary<string, string>? existingMetadata,
        IDictionary<string, string>? requestMetadata)
    {
        Dictionary<string, string>? updatedMetadata = existingMetadata == null ? null : new Dictionary<string, string>(existingMetadata);
        if (requestMetadata == null)
        {
            return updatedMetadata;
        }

        updatedMetadata ??= [];
        foreach (var kvp in requestMetadata)
        {
            updatedMetadata[kvp.Key] = kvp.Value;
        }

        return updatedMetadata;
    }
}

public sealed record AuthenticationHandshakeServiceDependencies(
    IOptions<AuthenticationHandshakeOptions>? Options = null,
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    IAuthenticationRateLimiter? RateLimiter = null);
