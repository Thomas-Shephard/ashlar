using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>
/// Defines the contract for iidentity service operations.
/// </summary>
public interface IIdentityService
{
    /// <summary>
    /// Gets the supported provider keys value.
    /// </summary>
    IEnumerable<AuthenticationProviderKey> SupportedProviderKeys { get; }

    /// <summary>
    /// Performs the find by email <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="email">The email value.</param>
    /// <param name="tenantId">The tenant id value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser?> FindByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the find by provider key <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="provider">The provider value.</param>
    /// <param name="providerKey">The provider key value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser?> FindByProviderKeyAsync(AuthenticationProviderKey provider, string providerKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the login <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="context">The context value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the create user <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="user">The user value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<IUser> CreateUserAsync(IUser user, CancellationToken cancellationToken = default);
    /// <summary>
    /// Performs the link credential <see langword="async" /> operation and returns the result.
    /// </summary>
    /// <param name="userId">The user id value.</param>
    /// <param name="assertion">The assertion value.</param>
    /// <param name="credentialValue">The credential value value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> LinkCredentialAsync(Guid userId, IAuthenticationAssertion assertion, string? credentialValue = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// Defines the available authentication status values.
/// </summary>
public enum AuthenticationStatus
{
    /// <summary>
    /// Represents the failed value.
    /// </summary>
    Failed = 0,
    /// <summary>
    /// Represents the success value.
    /// </summary>
    Success = 1,
    /// <summary>
    /// Represents the success with credential update value.
    /// </summary>
    SuccessWithCredentialUpdate = 2,
    /// <summary>
    /// Represents the disabled value.
    /// </summary>
    Disabled = 3,
    /// <summary>
    /// Represents the mfa required value.
    /// </summary>
    MfaRequired = 4
}

/// <summary>
/// Represents the authentication response data model.
/// </summary>
/// <param name="Succeeded">The succeeded value.</param>
/// <param name="User">The user value.</param>
/// <param name="Status">The status value.</param>
/// <param name="Claims">The claims value.</param>
public sealed record AuthenticationResponse(
    bool Succeeded,
    IUser? User = null,
    AuthenticationStatus Status = AuthenticationStatus.Failed,
    IDictionary<string, string>? Claims = null);
