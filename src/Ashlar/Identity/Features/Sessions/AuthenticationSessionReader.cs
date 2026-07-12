namespace Ashlar.Identity.Features.Sessions;

internal sealed class AuthenticationSessionReader(IAuthenticationSessionRepository repository, TimeProvider? timeProvider = null)
    : IAuthenticationSessionReader
{
    private readonly IAuthenticationSessionRepository _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(Guid userId, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();
        return (await _repository.ListSessionsForUserAsync(userId, request.ActiveOnly, now, cancellationToken))
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
    }
}
