
namespace Ashlar.Identity.Abstractions.Repositories;

/// <summary>
/// Defines the contract for iinvitation repository operations.
/// </summary>
public interface IInvitationRepository
{
    /// <summary>
    /// Performs the create invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="invitation">The invitation value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the get invitation by token hash <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="tokenHash">The token hash value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the update invitation <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="invitation">The invitation value.</param>
    /// <param name="expectedVersion">The expected version value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the revoke invitations by email <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
}
