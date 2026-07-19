namespace Ashlar.Identity.Abstractions.Services;

/// <summary>
/// Provides administrator-oriented automatic account lockout reset operations.
/// </summary>
/// <remarks>
/// Operations require an active actor session, fresh administration proof, explicit scope, host authorization, and durable audit.
/// Returned models contain only safe operational metadata and never include credential values, secrets, token material, or repository versions.
/// Reset operations are destructive administrative operations and require Ashlar's administration step-up proof.
/// Use <see cref="IAccountLockoutAdministrationReader" /> for visibility operations.
/// </remarks>
public interface IAccountLockoutAdministrationService
{
    /// <summary>
    /// Clears stored automatic lockout failures for a user and provider in an explicit tenant scope.
    /// </summary>
    /// <param name="actor">Authenticated administrator context.</param>
    /// <param name="userId">User whose automatic lockout state should be cleared.</param>
    /// <param name="provider">The authentication provider key.</param>
    /// <param name="request">Explicit tenant scope and required audit metadata for the reset.</param>
    /// <param name="cancellationToken">A token that can cancel lockout reset.</param>
    /// <returns>Stable reset outcome and the target scope.</returns>
    Task<Result<ResetAccountLockoutResult>> ResetLockoutAsync(
        AccountSecurityActorContext actor,
        Guid userId,
        AuthenticationProviderKey provider,
        ResetAccountLockoutRequest request,
        CancellationToken cancellationToken = default);
}
