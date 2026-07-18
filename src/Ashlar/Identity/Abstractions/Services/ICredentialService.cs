using Ashlar.Auditing;

namespace Ashlar.Identity.Abstractions.Services;

internal interface ICredentialService
{
    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(AuthenticationContext context, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(Guid userId, IAuthenticationAssertion assertion, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    Task<CredentialUsageUpdateResult> UpdateCredentialUsageAsync(UserCredential unprotectedCredential, UserCredential? originalCredential, AuthenticationResult result, IAuthenticationProvider provider, CancellationToken cancellationToken = default);

    Task<Result> LinkCredentialAsync(InternalCredentialLinkRequest request, CancellationToken cancellationToken = default);
}

internal interface IValidatedExternalCredentialLinkService
{
    Task<Result> LinkValidatedExternalCredentialAsync(InternalValidatedExternalCredentialLinkRequest request, CancellationToken cancellationToken = default);
}

internal sealed record InternalCredentialLinkRequest(
    Guid UserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    string? CredentialValue,
    string? CredentialMetadata,
    AuditContext Audit,
    Guid? TenantId = null);

internal sealed record InternalValidatedExternalCredentialLinkRequest(
    Guid UserId,
    ProviderType ProviderType,
    string ProviderName,
    string ProviderKey,
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
