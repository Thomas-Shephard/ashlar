namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Groups core identity dependencies to simplify service constructors.
/// </summary>
/// <param name="userRepository">Stores and retrieves users.</param>
/// <param name="credentialRepository">Stores and retrieves credentials.</param>
/// <param name="identityService">Coordinates identity workflows that need user and credential operations.</param>
/// <param name="transactionProvider">Creates transactions for multi-step identity workflows.</param>
internal sealed class IdentityContext(
    IUserRepository userRepository,
    ICredentialRepository credentialRepository,
    IIdentityService identityService,
    IAshlarTransactionProvider transactionProvider)
{
    /// <summary>
    /// Gets the user repository.
    /// </summary>
    public IUserRepository UserRepository { get; } = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    /// <summary>
    /// Gets the credential repository.
    /// </summary>
    public ICredentialRepository CredentialRepository { get; } = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
    /// <summary>
    /// Gets the identity service.
    /// </summary>
    public IIdentityService IdentityService { get; } = identityService ?? throw new ArgumentNullException(nameof(identityService));
    /// <summary>
    /// Gets the transaction provider.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
