namespace Ashlar.Identity.Features.Mfa;

/// <summary>
/// Implements framework-neutral step-up authentication freshness evaluation.
/// </summary>
/// <param name="sessionService">The session service value.</param>
/// <param name="timeProvider">The time provider value.</param>
public sealed class StepUpAuthenticationService(IAuthenticationSessionService? sessionService = null, TimeProvider? timeProvider = null) : IStepUpAuthenticationService
{
    private readonly IAuthenticationSessionService? _sessionService = sessionService;
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Initializes an evaluator-only service instance.
    /// </summary>
    /// <param name="timeProvider">The time provider value.</param>
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

        if (session.AdditionalVerificationAt == null)
        {
            return Failure(AshlarFailureCodes.StepUpRequired, "Additional verification is required.");
        }

        if (session.AdditionalVerificationAt.Value > now ||
            now - session.AdditionalVerificationAt.Value > request.Requirement.FreshnessWindow)
        {
            return Failure(AshlarFailureCodes.StepUpExpired, "Additional verification has expired.");
        }

        if (request.Requirement.AllowedProviders is { Count: > 0 } allowedProviders &&
            (session.AdditionalVerificationProvider == null || !allowedProviders.Contains(session.AdditionalVerificationProvider.Value)))
        {
            return Failure(AshlarFailureCodes.StepUpProviderNotAllowed, "Additional verification provider is not allowed.");
        }

        if (request.Requirement.AllowedFactors is { Count: > 0 } allowedFactors &&
            (string.IsNullOrWhiteSpace(session.AdditionalVerificationFactor) ||
             !allowedFactors.Contains(session.AdditionalVerificationFactor, StringComparer.OrdinalIgnoreCase)))
        {
            return Failure(AshlarFailureCodes.StepUpFactorNotAllowed, "Additional verification factor is not allowed.");
        }

        return StepUpEvaluationResult.Success;
    }

    /// <inheritdoc />
    public Task<Result<AuthenticationSession>> MarkVerifiedAsync(
        Guid userId,
        MarkSessionStepUpVerifiedRequest request,
        CancellationToken cancellationToken = default)
    {
        if (_sessionService == null)
        {
            throw new InvalidOperationException("A session service is required to mark step-up verification.");
        }

        return _sessionService.MarkStepUpVerifiedAsync(userId, request, cancellationToken);
    }

    private static StepUpEvaluationResult Failure(AshlarFailureCode code, string reason)
    {
        return new StepUpEvaluationResult(false, code, reason);
    }
}
