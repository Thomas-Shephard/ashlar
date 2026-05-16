using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

/// <summary>
/// Groups invitation persistence dependencies.
/// </summary>
/// <param name="invitationRepository">The invitation repository value.</param>
/// <param name="identityRepository">The identity repository value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
public sealed class InvitationStoreContext(
    IInvitationRepository invitationRepository,
    IIdentityRepository identityRepository,
    IAshlarTransactionProvider transactionProvider)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IInvitationRepository InvitationRepository { get; } = invitationRepository ?? throw new ArgumentNullException(nameof(invitationRepository));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IIdentityRepository IdentityRepository { get; } = identityRepository ?? throw new ArgumentNullException(nameof(identityRepository));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
