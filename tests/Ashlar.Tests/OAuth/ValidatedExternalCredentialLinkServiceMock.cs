using System.Linq.Expressions;
using Moq;

namespace Ashlar.Tests.OAuth;

internal sealed class ValidatedExternalCredentialLinkServiceMock : IValidatedExternalCredentialLinkService
{
    private Action<InternalValidatedExternalCredentialLinkRequest, CancellationToken>? _callback;
    private Result _result = Result.Success();

    public IValidatedExternalCredentialLinkService Object => this;

    public List<InternalValidatedExternalCredentialLinkRequest> Calls { get; } = [];

    public ValidatedExternalCredentialLinkServiceMock Setup(
        Expression<Func<IValidatedExternalCredentialLinkService, Task<Result>>> _) => this;

    public ValidatedExternalCredentialLinkServiceMock Callback<TRequest, TCancellationToken>(Action<TRequest, TCancellationToken> callback)
    {
        _callback = (request, cancellationToken) => callback((TRequest)(object)request, (TCancellationToken)(object)cancellationToken);
        return this;
    }

    public ValidatedExternalCredentialLinkServiceMock ReturnsAsync(Result result)
    {
        _result = result;
        return this;
    }

    public void Verify(
        Expression<Func<IValidatedExternalCredentialLinkService, Task<Result>>> _,
        Func<Times> times)
    {
        Assert.That(Calls, times().Equals(Times.Once()) ? Has.Count.EqualTo(1) : Is.Empty);
    }

    public Task<Result> LinkValidatedExternalCredentialAsync(
        InternalValidatedExternalCredentialLinkRequest request,
        CancellationToken cancellationToken = default)
    {
        Calls.Add(request);
        _callback?.Invoke(request, cancellationToken);
        return Task.FromResult(_result);
    }
}
