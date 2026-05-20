namespace Ashlar.Identity.Features.Infrastructure;

/// <summary>
/// Groups core identity dependencies to simplify service constructors.
/// </summary>
/// <param name="repository">The repository value.</param>
/// <param name="identityService">The identity service value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
internal sealed class IdentityContext(
    IIdentityRepository repository,
    IIdentityService identityService,
    IAshlarTransactionProvider transactionProvider)
{
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IIdentityRepository Repository { get; } = repository ?? throw new ArgumentNullException(nameof(repository));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IIdentityService IdentityService { get; } = identityService ?? throw new ArgumentNullException(nameof(identityService));
    /// <summary>
    /// Gets the configured dependency value.
    /// </summary>
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
