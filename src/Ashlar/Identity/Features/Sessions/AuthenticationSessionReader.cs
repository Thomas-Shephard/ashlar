namespace Ashlar.Identity.Features.Sessions;

internal sealed class AuthenticationSessionReader(IAuthenticationSessionRepository repository, TimeProvider? timeProvider = null)
    : IAuthenticationSessionInventoryReader
{
    private readonly IAuthenticationSessionRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsAsync(
        ValidatedAuthenticationSession session, ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();
        var current = await _repository.GetSessionAsync(session.Id, cancellationToken);
        if (current is null || current.Id != session.Id || current.UserId != session.UserId
            || !Nullable.Equals(current.TenantId, session.TenantId)
            || current.CreatedAt > now || current.ExpiresAt <= current.CreatedAt || !current.IsActive(now))
            return Result.Failure<IReadOnlyList<AuthenticationSessionSummary>>(AshlarFailureCodes.SessionNotFoundOrInactive);

        return await ListSessionsForUserAsync(session.UserId, session.TenantId,
            request with { CurrentSessionId = session.Id }, cancellationToken);
    }

    public async Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsForUserAsync(
        Guid userId, Guid? tenantId, ListAuthenticationSessionsRequest request,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();
        var sessions = await _repository.ListSessionsForUserAsync(userId, request.ActiveOnly, now, cancellationToken);
        if (sessions is null || sessions.Any(item => item.Id == Guid.Empty || item.UserId != userId
            || !Nullable.Equals(item.TenantId, tenantId)
            || item.CreatedAt > now || item.ExpiresAt <= item.CreatedAt
            || request.ActiveOnly && !item.IsActive(now)))
            return Result.Failure<IReadOnlyList<AuthenticationSessionSummary>>(AshlarFailureCodes.TenantMismatch);

        IReadOnlyList<AuthenticationSessionSummary> summaries = sessions
            .Select(session => new AuthenticationSessionSummary
            {
                Id = session.Id,
                CreatedAt = session.CreatedAt,
                ExpiresAt = session.ExpiresAt,
                LastSeenAt = session.LastSeenAt,
                RevokedAt = session.RevokedAt,
                RevocationReason = session.RevocationReason,
                IpAddress = session.IpAddress,
                UserAgent = session.UserAgent,
                Metadata = session.Metadata,
                IsCurrent = request.CurrentSessionId.HasValue && session.Id == request.CurrentSessionId.Value,
                IsActive = session.IsActive(now)
            }).ToList().AsReadOnly();
        return Result.Success(summaries);
    }
}
