using Ashlar.Auditing;

namespace Ashlar.Identity.Features.Credentials;

internal sealed class ExternalAccountCredentialLinker(
    IUserRepository userRepository,
    ICredentialLinkingInfrastructure credentialLinking,
    TimeProvider timeProvider)
    : IExternalAccountCredentialLinker
{
    public const string LinkPurpose = "external-account-linking";

    private readonly IUserRepository _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    private readonly ICredentialLinkingInfrastructure _credentialLinking = credentialLinking ?? throw new ArgumentNullException(nameof(credentialLinking));
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

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

        var proofFailure = FreshVerificationProofValidator.ValidateMfaProof(
            request.CurrentUserId,
            request.Tenant,
            request.FreshMfaProof,
            request.CurrentSessionId,
            _timeProvider.GetUtcNow(),
            LinkPurpose);
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
            request.CurrentUserId,
            request.Assertion,
            request.Provider,
            credentialValue: null,
            credentialMetadata: request.CredentialMetadata,
            audit: request.Audit,
            tenantId: request.Tenant.TenantId,
            cancellationToken: cancellationToken);
    }
}

internal interface ICredentialLinkingInfrastructure
{
    Task<Result> LinkCredentialAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        string? credentialValue,
        string? credentialMetadata,
        AuditContext? audit,
        Guid? tenantId,
        CancellationToken cancellationToken);
}
