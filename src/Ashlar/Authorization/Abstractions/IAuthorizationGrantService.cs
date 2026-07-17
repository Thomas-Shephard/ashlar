using Ashlar.Authorization.Models;

namespace Ashlar.Authorization.Abstractions;

/// <summary>
/// Creates and revokes authorization grants.
/// </summary>
/// <remarks>Creation and revocation require an Ashlar-issued purpose-bound fresh MFA proof, its current session, matching audit actor identity, explicit scope, approval from the configured host authorizer, and durable audit in the same Ashlar transaction as the grant mutation. Revoking or expiring the proof's source session immediately invalidates it.</remarks>
public interface IAuthorizationGrantService
{
    /// <summary>Purpose required on fresh MFA proofs authorizing grant administration.</summary>
    public const string AdministrationProofPurpose = "authorization-grant-administration";

    /// <summary>
    /// Creates a role or permission grant after actor proof, session, audit identity, host authorization, scope, and tenant ownership validation.
    /// </summary>
    /// <param name="request">Actor-bound grant details with explicit tenant or global scope and required audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel grant creation.</param>
    /// <returns>Created grant when validation and tenant checks succeed.</returns>
    Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a grant after actor proof, session, audit identity, host authorization, and explicit scope validation.
    /// </summary>
    /// <param name="request">Actor-bound grant identifier with explicit tenant or global scope and required audit metadata.</param>
    /// <param name="cancellationToken">A token that can cancel grant revocation.</param>
    /// <returns>Revocation result with the grant id, requested tenant boundary, and outcome.</returns>
    Task<RevokeAuthorizationGrantResult> RevokeGrantAsync(RevokeAuthorizationGrantRequest request, CancellationToken cancellationToken = default);
}

internal interface IAuthorizationGrantBootstrapService
{
    Task<Result<AuthorizationGrant>> CreateGrantAsync(CreateAuthorizationGrantRequest request, CancellationToken cancellationToken = default);
}
