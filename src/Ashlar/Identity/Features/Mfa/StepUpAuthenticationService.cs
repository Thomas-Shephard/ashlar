namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Implements framework-neutral step-up authentication freshness evaluation.
/// </summary>
/// <param name="sessionService">Optional session service used to persist successful step-up verification.</param>
/// <param name="timeProvider">Clock used to evaluate freshness windows.</param>
public sealed class StepUpAuthenticationService(IAuthenticationSessionService? sessionService = null, TimeProvider? timeProvider = null) : IStepUpAuthenticationService
{
    private readonly IAuthenticationSessionService? _sessionService = sessionService;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Initializes an evaluator-only service instance.
    /// </summary>
    /// <param name="timeProvider">Clock used to evaluate freshness windows.</param>
    public StepUpAuthenticationService(TimeProvider timeProvider)
        : this(null, timeProvider)
    {
    }

    /// <inheritdoc />
    public StepUpEvaluationResult Evaluate(StepUpEvaluationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Requirement);
        if (request.Requirement.FreshnessWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(request), request.Requirement.FreshnessWindow, "Step-up freshness window must be positive.");
        }

        var now = _timeProvider.GetUtcNow();
        var session = request.Session;
        if (session == null || !session.IsActive(now))
        {
            return Failure(AshlarFailureCodes.SessionNotFoundOrInactive, "Session was not found or is inactive.");
        }

        return EvaluatePosture(session.AdditionalVerificationAt, session.AdditionalVerificationProvider,
            session.AdditionalVerificationFactor, request.Requirement, now);
    }

    private static StepUpEvaluationResult EvaluatePosture(
        DateTimeOffset? verifiedAt,
        AuthenticationProviderKey? provider,
        string? factor,
        StepUpRequirement requirement,
        DateTimeOffset now)
    {
        if (verifiedAt == null)
        {
            return Failure(AshlarFailureCodes.StepUpRequired, "Additional verification is required.");
        }

        if (verifiedAt.Value > now || now - verifiedAt.Value >= requirement.FreshnessWindow)
        {
            return Failure(AshlarFailureCodes.StepUpExpired, "Additional verification has expired.");
        }

        if (requirement.AllowedProviders is { Count: > 0 } allowedProviders &&
            (provider == null || !allowedProviders.Contains(provider.Value)))
        {
            return Failure(AshlarFailureCodes.StepUpProviderNotAllowed, "Additional verification provider is not allowed.");
        }

        if (requirement.AllowedFactors is { Count: > 0 } allowedFactors &&
            (string.IsNullOrWhiteSpace(factor) || !allowedFactors.Contains(factor, StringComparer.OrdinalIgnoreCase)))
        {
            return Failure(AshlarFailureCodes.StepUpFactorNotAllowed, "Additional verification factor is not allowed.");
        }

        return StepUpEvaluationResult.Success;
    }

    /// <summary>Creates a fresh-MFA proof from an Ashlar-validated session.</summary>
    /// <param name="session">Ashlar-validated session capability.</param>
    /// <param name="requirement">Freshness and posture requirement.</param>
    /// <returns>A scoped proof, or failure when the requirement is not satisfied.</returns>
    public Result<FreshMfaVerificationProof> CreateFreshMfaProof(ValidatedAuthenticationSession session, StepUpRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(requirement);
        if (requirement.FreshnessWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(requirement), requirement.FreshnessWindow, "Step-up freshness window must be positive.");
        }

        var now = _timeProvider.GetUtcNow();
        var evaluation = session.ExpiresAt > now
            ? EvaluatePosture(session.AdditionalVerificationAt, session.AdditionalVerificationProvider,
                session.AdditionalVerificationFactor, requirement, now)
            : Failure(AshlarFailureCodes.SessionNotFoundOrInactive, "Session was not found or is inactive.");
        if (!evaluation.Succeeded)
        {
            var failureCode = evaluation.FailureCode.GetValueOrDefault(AshlarFailureCodes.StepUpRequired);
            return Result.Failure<FreshMfaVerificationProof>(failureCode);
        }

        var verifiedAt = session.AdditionalVerificationAt!.Value;

        return Result.Success(new FreshMfaVerificationProof(
            session.UserId,
            session.TenantId,
            session.Id,
            verifiedAt,
            ProofExpiry(verifiedAt, requirement.FreshnessWindow, session.ExpiresAt),
            requirement.Purpose));
    }

    /// <summary>Creates a fresh-primary-authentication proof from an Ashlar-validated session.</summary>
    /// <param name="session">Ashlar-validated session capability.</param>
    /// <param name="freshnessWindow">Maximum age of primary authentication.</param>
    /// <param name="purpose">Optional operation purpose.</param>
    /// <returns>A scoped proof, or failure when the requirement is not satisfied.</returns>
    public Result<FreshPrimaryAuthenticationProof> CreateFreshPrimaryAuthenticationProof(ValidatedAuthenticationSession session, TimeSpan freshnessWindow, string? purpose = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (freshnessWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(freshnessWindow), freshnessWindow, "Primary-authentication freshness window must be positive.");
        }

        var now = _timeProvider.GetUtcNow();
        if (session.ExpiresAt <= now)
        {
            return Result.Failure<FreshPrimaryAuthenticationProof>(AshlarFailureCodes.SessionNotFoundOrInactive);
        }

        if (session.AuthenticatedAt == null)
        {
            return Result.Failure<FreshPrimaryAuthenticationProof>(AshlarFailureCodes.StepUpRequired);
        }

        if (session.AuthenticatedAt.Value > now || now - session.AuthenticatedAt.Value >= freshnessWindow)
        {
            return Result.Failure<FreshPrimaryAuthenticationProof>(AshlarFailureCodes.StepUpExpired);
        }

        return Result.Success(new FreshPrimaryAuthenticationProof(
            session.UserId,
            session.TenantId,
            session.Id,
            session.AuthenticatedAt.Value,
            ProofExpiry(session.AuthenticatedAt.Value, freshnessWindow, session.ExpiresAt),
            purpose));
    }

    /// <inheritdoc />
    public Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        MfaAuthenticationResult authenticationResult,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default)
    {
        if (_sessionService == null)
        {
            throw new InvalidOperationException("A session service is required to mark step-up verification.");
        }

        return _sessionService.MarkStepUpVerifiedAsync(authenticationResult, request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        AuthenticationResponse authenticationResponse,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default)
    {
        if (_sessionService == null)
        {
            throw new InvalidOperationException("A session service is required to mark step-up verification.");
        }

        ArgumentNullException.ThrowIfNull(authenticationResponse);
        var user = authenticationResponse.StepUpVerifiedUser;
        if (user == null)
        {
            return Task.FromResult(Result.Failure<AuthenticationSession>(AshlarFailureCodes.StepUpRequired, "Step-up marking requires a successful Ashlar factor verification response."));
        }

        var result = new MfaAuthenticationResult(MfaAuthenticationStatus.Succeeded, user, FreshMfaSatisfied: true)
        {
            StepUpSessionMarkingProof = authenticationResponse.StepUpSessionMarkingProof
        };
        return _sessionService.MarkStepUpVerifiedAsync(result, request, cancellationToken);
    }

    private static StepUpEvaluationResult Failure(AshlarFailureCode code, string reason)
    {
        return new StepUpEvaluationResult(false, code, reason);
    }

    private static DateTimeOffset ProofExpiry(DateTimeOffset ceremonyAt, TimeSpan window, DateTimeOffset sessionExpiresAt)
    {
        var ceremonyUtc = ceremonyAt.ToUniversalTime();
        var sessionExpiryUtc = sessionExpiresAt.ToUniversalTime();
        return window >= sessionExpiryUtc - ceremonyUtc ? sessionExpiryUtc : ceremonyUtc + window;
    }
}
