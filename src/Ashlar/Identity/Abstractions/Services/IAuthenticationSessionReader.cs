namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Lists the current user's safe authentication session summaries from a validated, still-active Ashlar session.</summary>
public interface IAuthenticationSessionReader
{
    /// <summary>Lists sessions owned by the validated session's user and tenant without returning raw session tokens.</summary>
    /// <param name="session">Capability produced by successful Ashlar session validation. The backing session is rechecked for activity and ownership.</param>
    /// <param name="request">Active-session filtering and current-session marker options for the list operation.</param>
    /// <param name="cancellationToken">A token that can cancel the query.</param>
    /// <returns>Safe session summaries, or a failure when the capability is inactive or a provider violates ownership or lifecycle invariants.</returns>
    Task<Result<IReadOnlyList<AuthenticationSessionSummary>>> ListSessionsAsync(ValidatedAuthenticationSession session, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default);
}
