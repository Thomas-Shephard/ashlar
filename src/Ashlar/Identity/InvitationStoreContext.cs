using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

/// <summary>
/// Groups invitation persistence dependencies.
/// </summary>
public sealed class InvitationStoreContext(
    IInvitationRepository invitationRepository,
    IIdentityRepository identityRepository,
    IAshlarTransactionProvider transactionProvider)
{
    public IInvitationRepository InvitationRepository { get; } = invitationRepository ?? throw new ArgumentNullException(nameof(invitationRepository));
    public IIdentityRepository IdentityRepository { get; } = identityRepository ?? throw new ArgumentNullException(nameof(identityRepository));
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
