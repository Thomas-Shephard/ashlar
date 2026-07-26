namespace Ashlar.Identity.Features.Services;

internal sealed class IdentityService(
    IAuthenticationProviderRegistry providerRegistry,
    IAuthenticationPipeline authenticationPipeline)
    : IIdentityService
{
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly IAuthenticationPipeline _authenticationPipeline = authenticationPipeline ?? throw new ArgumentNullException(nameof(authenticationPipeline));

    public IEnumerable<AuthenticationProviderKey> SupportedProviderKeys => _providerRegistry.SupportedProviderKeys;

    public async Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        return await _authenticationPipeline.LoginAsync(context, assertion, cancellationToken);
    }
}
