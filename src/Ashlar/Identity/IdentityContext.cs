using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

/// <summary>
/// Groups core identity dependencies to simplify service constructors.
/// </summary>
public sealed class IdentityContext(
    IIdentityRepository repository,
    IIdentityService identityService,
    IAshlarTransactionProvider transactionProvider)
{
    public IIdentityRepository Repository { get; } = repository ?? throw new ArgumentNullException(nameof(repository));
    public IIdentityService IdentityService { get; } = identityService ?? throw new ArgumentNullException(nameof(identityService));
    public IAshlarTransactionProvider TransactionProvider { get; } = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
}
