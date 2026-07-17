namespace Ashlar.Identity.Features.Invitations;

internal sealed class InvitationStoreContext(
    IInvitationRepository invitationRepository,
    IUserRepository userRepository,
    AshlarDurableTransactionProvider transactionProvider)
{
    public IInvitationRepository InvitationRepository { get; } = invitationRepository ?? throw new ArgumentNullException(nameof(invitationRepository));
    public IUserRepository UserRepository { get; } = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    public AshlarDurableTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
