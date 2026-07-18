using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

internal interface ICredentialService
{
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(AuthenticationContext context, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    Task<CredentialUsageUpdateResult> UpdateCredentialUsageAsync(UserCredential unprotectedCredential, UserCredential? originalCredential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    Task<Result> LinkCredentialAsync(InternalCredentialLinkRequest request, CancellationToken cancellationToken = default);
}

/// <summary>Links provider-owned credentials through Ashlar's durable security mutation boundary.</summary>
public interface ICredentialLinkService
{
    /// <summary>Links a credential to an existing user.</summary>
    /// <param name="request">The credential mutation and audit context.</param>
    /// <param name="cancellationToken">A token that can cancel linking.</param>
    /// <returns>Success when linked; otherwise, a stable failure code.</returns>
    Task<Result> LinkCredentialAsync(CredentialLinkRequest request, CancellationToken cancellationToken = default);
}

/// <summary>Describes a credential-link mutation.</summary>
/// <param name="UserId">User receiving the credential.</param>
/// <param name="Assertion">Authentication assertion used to derive the external key.</param>
/// <param name="Provider">Authentication provider owning the credential.</param>
/// <param name="Audit">Required audit context.</param>
/// <param name="TenantId">Expected tenant identifier, or <see langword="null" /> for a global user.</param>
public sealed record CredentialLinkRequest(
    Guid UserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    AuditContext Audit,
    Guid? TenantId = null);

internal sealed record InternalCredentialLinkRequest(
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
