using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

/// <summary>Provides documented behavior for this member.</summary>
/// <returns>The operation result.</returns>
public interface IAuthenticationHandshakeService
{
    /// <summary>Provides documented behavior for this member.</summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(CreateAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>Provides documented behavior for this member.</summary>
    /// <param name="request">The request value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result<AuthenticationHandshake>> VerifyFactorAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default);

    /// <summary>Provides documented behavior for this member.</summary>
    /// <param name="handshakeToken">The handshake token value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<AuthenticationHandshake?> GetHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);

    /// <summary>Provides documented behavior for this member.</summary>
    /// <param name="handshakeToken">The handshake token value.</param>
    /// <param name="cancellationToken">The cancellation token value.</param>
    /// <returns>The operation result.</returns>
    Task<Result> RevokeHandshakeAsync(string handshakeToken, CancellationToken cancellationToken = default);
}
