namespace Ashlar.Tests.Support;

internal sealed class TestAuthenticationHandshakeCompletionService : IAuthenticationHandshakeCompletionService
{
    public Result<AuthenticationHandshake> CompletionResult { get; set; } = Result.Failure<AuthenticationHandshake>(AshlarFailureCodes.HandshakeNotFound);

    public List<VerifyAuthenticationHandshakeRequest> Calls { get; } = [];

    public Task<Result<AuthenticationHandshake>> CompleteFactorVerificationAsync(VerifyAuthenticationHandshakeRequest request, CancellationToken cancellationToken = default)
    {
        Calls.Add(request);
        return Task.FromResult(CompletionResult);
    }
}

