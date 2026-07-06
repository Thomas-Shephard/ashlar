namespace Ashlar.Tests.Identity.Features.TestDoubles;

internal sealed class TestCredentialService : ICredentialService
{
    public List<LinkCredentialCall> LinkCalls { get; } = [];
    public Result LinkResult { get; set; } = Result.Success();
    public (IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed) ContextResolveResult { get; set; }
    public (IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed) UserResolveResult { get; set; }
    public CredentialUsageUpdateResult UsageUpdateResult { get; set; } = CredentialUsageUpdateResult.NotNeeded;
    public Exception? UsageUpdateException { get; set; }
    public Func<Task<CredentialUsageUpdateResult>>? UsageUpdateHandler { get; set; }
    public int ContextResolveCalls { get; private set; }
    public int UserResolveCalls { get; private set; }
    public int UsageUpdateCalls { get; private set; }

    public Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        AuthenticationContext context,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        ContextResolveCalls++;
        return Task.FromResult(ContextResolveResult);
    }

    public Task<(IUser? User, UserCredential? Credential, UserCredential? OriginalCredential, bool UnprotectFailed)> ResolveAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        UserResolveCalls++;
        return Task.FromResult(UserResolveResult);
    }

    public Task<Result> LinkCredentialAsync(
        Guid userId,
        IAuthenticationAssertion assertion,
        IAuthenticationProvider provider,
        string? credentialValue = null,
        string? credentialMetadata = null,
        CancellationToken cancellationToken = default)
    {
        LinkCalls.Add(new LinkCredentialCall(userId, assertion, provider, credentialValue, credentialMetadata));
        return Task.FromResult(LinkResult);
    }

    public Task<CredentialUsageUpdateResult> UpdateCredentialUsageAsync(
        UserCredential unprotectedCredential,
        UserCredential? originalCredential,
        AuthenticationResult result,
        IAuthenticationProvider provider,
        CancellationToken cancellationToken = default)
    {
        UsageUpdateCalls++;
        if (UsageUpdateException != null)
        {
            throw UsageUpdateException;
        }

        if (UsageUpdateHandler != null)
        {
            return UsageUpdateHandler();
        }

        return Task.FromResult(UsageUpdateResult);
    }
}

internal sealed record LinkCredentialCall(
    Guid UserId,
    IAuthenticationAssertion Assertion,
    IAuthenticationProvider Provider,
    string? CredentialValue,
    string? CredentialMetadata);
