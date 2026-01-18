using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Provides services for resolving, linking, and managing the lifecycle of user credentials.
/// </summary>
public interface ICredentialService
{
    /// <summary>
    /// Resolves the user and their associated credential based on the provided email and assertion.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <param name="tenantId">The optional tenant ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item><description><c>User</c>: The resolved user, or <c>null</c> if not found.</description></item>
    /// <item><description><c>Credential</c>: The unprotected user credential, or <c>null</c> if not found.</description></item>
    /// <item><description><c>OriginalCredential</c>: The original (potentially protected) user credential from the repository.</description></item>
    /// <item><description><c>UnprotectFailed</c>: A value indicating whether the credential failed to unprotect.</description></item>
    /// </list>
    /// </returns>
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(string email, IAuthenticationAssertion assertion, IAuthenticationProvider provider, Guid? tenantId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the user and their associated credential based on the provided user ID and assertion.
    /// </summary>
    /// <param name="userId">The user's unique ID.</param>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// A tuple containing the resolved user, unprotected credential, original credential, and unprotect status.
    /// </returns>
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Links a new credential to an existing user.
    /// </summary>
    /// <param name="userId">The user's unique ID.</param>
    /// <param name="assertion">The authentication assertion.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <param name="credentialValue">The optional raw credential value to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, string? credentialValue = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the usage information and potentially the secret value of a credential after a successful authentication attempt.
    /// </summary>
    /// <param name="unprotectedCredential">The unprotected credential to update.</param>
    /// <param name="originalCredential">The original protected credential for preservation if no update is requested.</param>
    /// <param name="result">The authentication result containing update instructions.</param>
    /// <param name="provider">The authentication provider.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task UpdateCredentialUsageAsync(UserCredential unprotectedCredential, UserCredential? originalCredential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default);
}