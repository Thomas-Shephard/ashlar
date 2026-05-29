namespace Ashlar.Identity.Features.Bootstrap;

/// <summary>
/// Groups bootstrap persistence dependencies.
/// </summary>
/// <param name="stateRepository">Reads and marks bootstrap initialization state.</param>
/// <param name="userRepository">Stores and retrieves users created or activated through bootstrap.</param>
/// <param name="transactionProvider">Creates transactions for bootstrap workflows.</param>
internal sealed class BootstrapStoreContext(
    IBootstrapStateRepository stateRepository,
    IUserRepository userRepository,
    IAshlarTransactionProvider transactionProvider)
{
    /// <summary>
    /// Gets the bootstrap state repository.
    /// </summary>
    public IBootstrapStateRepository StateRepository { get; } = stateRepository ?? throw new ArgumentNullException(nameof(stateRepository));
    /// <summary>
    /// Gets the user repository.
    /// </summary>
    public IUserRepository UserRepository { get; } = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    /// <summary>
    /// Gets the transaction provider.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
