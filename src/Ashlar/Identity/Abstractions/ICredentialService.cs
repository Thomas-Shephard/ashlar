using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides services for resolving, linking, and managing the lifecycle of user credentials.
/// </summary>
public interface ICredentialService
{
    /// <summary>
    /// Resolves the user and their associated credential based on the provided authentication context and assertion.
    /// </summary>
    /// <param name="context">The authentication context.</param>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A tuple containing:
    /// <list type="bullet">
    /// <item><description><c>User</c>: The resolved user, or <see langword="null" /> if not found.</description></item>
    /// <item><description><c>Credential</c>: The unprotected user credential, or <see langword="null" /> if not found.</description></item>
    /// <item><description><c>OriginalCredential</c>: The original (potentially protected) user credential from the repository.</description></item>
    /// <item><description><c>UnprotectFailed</c>: A value indicating whether the credential failed to unprotect.</description></item>
    /// </list>
    /// </returns>
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(AuthenticationContext context, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Provides behavior for task.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>A tuple containing the resolved user, unprotected credential, original credential, and unprotect status.
    /// </returns>
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Links a new credential to an existing user.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="provider">The provider value.</param>
    /// <param name="credentialValue">The credential value value.</param>
    /// <param name="initialMetadata">The initial metadata value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, string? credentialValue = null, string? initialMetadata = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the usage information, consumes, or potentially changes the secret value of a credential after a successful authentication attempt.
    /// </summary>
    /// <param name="unprotectedCredential">The unprotected credential value.</param>
    /// <param name="originalCredential">The original credential value.</param>
    /// <param name="result">The converted result value.</param>
    /// <param name="provider">The provider value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<bool> UpdateCredentialUsageAsync(UserCredential unprotectedCredential, UserCredential? originalCredential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default);
}
