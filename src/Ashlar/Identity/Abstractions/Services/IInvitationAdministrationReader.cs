namespace Ashlar.Identity.Abstractions.Services;

/// <summary>Reads display-safe invitation administration data without enabling revocation.</summary>
public interface IInvitationAdministrationReader
{
    /// <summary>Searches invitations for administrator and operations interfaces.</summary>
    /// <param name="request">Explicit tenant scope, filters, and paging options.</param>
    /// <param name="cancellationToken">A token that can cancel the search.</param>
    /// <returns>Provider-neutral invitation summaries without raw tokens or token hashes.</returns>
    Task<Result<InvitationSearchResult>> SearchInvitationsAsync(SearchInvitationsRequest request, CancellationToken cancellationToken = default);

    /// <summary>Gets a display-safe invitation projection by identifier.</summary>
    /// <param name="request">Explicit tenant scope and invitation identifier.</param>
    /// <param name="cancellationToken">A token that can cancel the lookup.</param>
    /// <returns>A safe invitation projection, or a not-found failure.</returns>
    Task<Result<InvitationAdministrationSummary>> GetInvitationAsync(InvitationAdministrationLookupRequest request, CancellationToken cancellationToken = default);
}
