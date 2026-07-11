using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Credentials;

internal sealed class ExternalAccountCredentialLinker(
    IUserRepository userRepository,
    ICredentialLinkingInfrastructure credentialLinking,
    ActiveSessionFreshProofValidator proofValidator)
    : IExternalAccountCredentialLinker
{
    public const string LinkPurpose = "external-account-linking";

    private readonly IUserRepository _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    private readonly ICredentialLinkingInfrastructure _credentialLinking = credentialLinking ?? throw new ArgumentNullException(nameof(credentialLinking));
    private readonly ActiveSessionFreshProofValidator _proofValidator = proofValidator ?? throw new ArgumentNullException(nameof(proofValidator));

    public async Task<Result> LinkExternalAccountCredentialAsync(ExternalAccountCredentialLinkRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Assertion);
        ArgumentNullException.ThrowIfNull(request.Provider);
        ArgumentNullException.ThrowIfNull(request.Tenant);

        if (request.Provider.Key.Type != ProviderType.OAuth && request.Provider.Key.Type != ProviderType.Oidc)
        {
            return Result.Failure(AshlarFailureCodes.ValidationError);
        }

        var proofFailure = await _proofValidator.ValidateAsync(
            request.CurrentUserId,
            request.Tenant,
            request.FreshMfaProof,
            request.CurrentSessionId,
            LinkPurpose,
            cancellationToken);
        if (proofFailure is { } failureCode)
        {
            return Result.Failure(failureCode);
        }

        var user = await _userRepository.GetUserByIdAsync(request.CurrentUserId, cancellationToken);
        if (user == null)
        {
            return Result.Failure(AshlarFailureCodes.UserNotFound);
        }

        if (!UserTenantOwnership.Matches(user, request.Tenant.TenantId))
        {
            return Result.Failure(AshlarFailureCodes.TenantMismatch);
        }

        return await _credentialLinking.LinkCredentialAsync(
            new CredentialLinkInfrastructureRequest(
                request.CurrentUserId,
                request.Assertion,
                request.Provider,
                CredentialValue: null,
                request.CredentialMetadata,
                request.Audit,
                request.Tenant.TenantId),
            cancellationToken: cancellationToken);
    }
}

internal interface ICredentialLinkingInfrastructure
{
    Task<Result> LinkCredentialAsync(
        CredentialLinkInfrastructureRequest request,
        CancellationToken cancellationToken);
}

internal sealed record CredentialLinkInfrastructureRequest(
    Guid UserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    string? CredentialValue,
    string? CredentialMetadata,
    AuditContext? Audit,
    Guid? TenantId);
