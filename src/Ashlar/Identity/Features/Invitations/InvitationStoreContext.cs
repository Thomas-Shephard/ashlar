namespace Ashlar.Identity.Features.Invitations;

/// <summary>
/// Groups invitation persistence dependencies.
/// </summary>
/// <param name="invitationRepository">Stores and retrieves invitation records.</param>
/// <param name="userRepository">Stores and retrieves users created or updated through invitation acceptance.</param>
/// <param name="transactionProvider">Creates transactions for invitation workflows.</param>
public sealed class InvitationStoreContext(
    IInvitationRepository invitationRepository,
    IUserRepository userRepository,
    IAshlarTransactionProvider transactionProvider)
{
    /// <summary>
    /// Gets the invitation repository.
    /// </summary>
    public IInvitationRepository InvitationRepository { get; } = invitationRepository ?? throw new ArgumentNullException(nameof(invitationRepository));
    /// <summary>
    /// Gets the user repository.
    /// </summary>
    public IUserRepository UserRepository { get; } = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    /// <summary>
    /// Gets the transaction provider.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
