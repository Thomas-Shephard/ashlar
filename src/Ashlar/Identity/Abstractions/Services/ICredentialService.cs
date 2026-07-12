using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Resolves protected user credentials and persists provider-owned credential lifecycle changes.
/// </summary>
internal interface ICredentialService
{
    /// <summary>
    /// Resolves the user and provider-owned credential for an authentication attempt.
    /// </summary>
    /// <param name="context">Tenant, audit, and rate-limit context for the authentication attempt.</param>
    /// <param name="assertion">Credential material supplied for the assertion. Treat as sensitive unless documented otherwise.</param>
    /// <param name="provider">Authenticator implementation that owns the credential lookup.</param>
    /// <param name="cancellationToken">A token that can cancel credential resolution.</param>
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
    /// Resolves a provider-owned credential for a known user.
    /// </summary>
    /// <param name="userId">The user that must own the credential.</param>
    /// <param name="assertion">Credential material supplied for the assertion. Treat as sensitive unless documented otherwise.</param>
    /// <param name="provider">Authenticator implementation that owns the credential lookup.</param>
    /// <param name="cancellationToken">A token that can cancel credential resolution.</param>
    /// <returns>A tuple containing the resolved user, unprotected credential, original credential, and unprotect status.
    /// </returns>
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Infrastructure hook for provider-owned account-security flows to persist a provider-derived credential for an existing user.
    /// </summary>
    /// <param name="request">The provider-owned credential mutation and its required audit context.</param>
    /// <param name="cancellationToken">A token that can cancel linking.</param>
    /// <returns>Success when the credential is linked; otherwise, a stable failure describing why linking was rejected.</returns>
    Task<Result> LinkCredentialAsync(CredentialLinkRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the usage information, consumes, or potentially changes the secret value of a credential after a successful authentication attempt.
    /// </summary>
    /// <param name="unprotectedCredential">The credential used during authentication after any repository protection has been removed.</param>
    /// <param name="originalCredential">The original repository credential, when different from <paramref name="unprotectedCredential" />.</param>
    /// <param name="result">Authentication decision that may request credential consumption or replacement.</param>
    /// <param name="provider">Authenticator implementation that owns the credential.</param>
    /// <param name="cancellationToken">A token that can cancel the update.</param>
    /// <returns>A result that states whether authentication may continue and whether an update was persisted.</returns>
    Task<CredentialUsageUpdateResult> UpdateCredentialUsageAsync(UserCredential unprotectedCredential, UserCredential? originalCredential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default);
}

/// <summary>Provider-owned credential mutation with required audit context.</summary>
internal sealed record CredentialLinkRequest(
    Guid UserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    string? CredentialValue,
    string? CredentialMetadata,
    AuditContext Audit,
    Guid? TenantId = null);

/// <summary>
/// Result of persisting credential usage, consumption, or replacement after provider authentication.
/// </summary>
/// <param name="CanProceed">Whether authentication may continue after applying required credential lifecycle rules.</param>
/// <param name="UpdatePersisted">Whether all provider-requested credential data changes were actually persisted.</param>
public sealed record CredentialUsageUpdateResult(bool CanProceed, bool UpdatePersisted)
{
    /// <summary>
    /// Authentication may continue and the provider-requested credential update was persisted.
    /// </summary>
    public static CredentialUsageUpdateResult Persisted { get; } = new(true, true);

    /// <summary>
    /// Authentication may continue and no provider-requested credential update was persisted.
    /// </summary>
    public static CredentialUsageUpdateResult NotNeeded { get; } = new(true, false);

    /// <summary>
    /// Authentication may continue even though a best-effort provider-requested credential update was not persisted.
    /// </summary>
    public static CredentialUsageUpdateResult BestEffortFailed { get; } = new(true, false);

    /// <summary>
    /// Authentication must fail because a required credential lifecycle mutation was not persisted.
    /// </summary>
    public static CredentialUsageUpdateResult RequiredFailed { get; } = new(false, false);
}
