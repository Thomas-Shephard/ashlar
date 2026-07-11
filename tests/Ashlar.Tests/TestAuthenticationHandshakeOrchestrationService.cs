namespace Ashlar.Tests;

/// <summary>
/// Mockable test double for Ashlar's internal handshake orchestration contract.
/// </summary>
public class TestAuthenticationHandshakeOrchestrationService : IAuthenticationHandshakeOrchestrationService
{
    /// <inheritdoc />
    public virtual Task<Result<AuthenticationHandshakeCreated>> CreateHandshakeAsync(CreateAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public virtual Task<Result<AuthenticationHandshake>> BeginFactorChallengeAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public virtual Task<Result<AuthenticationHandshake>> BeginVerificationAsync(BeginAuthenticationHandshakeVerificationRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public virtual Task<Result<AuthenticationHandshake>> BeginFactorVerificationAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    /// <inheritdoc />
    public virtual Task<Result> RevokeHandshakeAsync(string? handshakeToken, AuthenticationContext? context = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}
