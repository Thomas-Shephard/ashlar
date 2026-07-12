namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Lists safe authentication session summaries without enabling session mutation.</summary>
public interface IAuthenticationSessionReader
{
    /// <summary>Lists authentication sessions for a user without returning raw session tokens.</summary>
    /// <param name="userId">The user whose sessions will be listed.</param>
    /// <param name="request">Active-session filtering and current-session marker options for the list operation.</param>
    /// <param name="cancellationToken">A token that can cancel the query.</param>
    /// <returns>Safe session summaries.</returns>
    Task<IReadOnlyList<AuthenticationSessionSummary>> ListSessionsForUserAsync(Guid userId, ListAuthenticationSessionsRequest request, CancellationToken cancellationToken = default);
}
