using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;

namespace Ashlar.Identity;

public sealed class AuthenticationPipeline(
    IAuthenticationProviderRegistry providerRegistry,
    ICredentialService credentialService)
    : IAuthenticationPipeline
{
    private readonly IAuthenticationProviderRegistry _providerRegistry = providerRegistry ?? throw new ArgumentNullException(nameof(providerRegistry));
    private readonly ICredentialService _credentialService = credentialService ?? throw new ArgumentNullException(nameof(credentialService));

    public async Task<AuthenticationResponse> LoginAsync(AuthenticationContext context, IAuthenticationAssertion assertion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_providerRegistry.TryGetProvider(assertion, context, out var provider))
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        var (user, credential, originalCredential, unprotectFailed) = await _credentialService.ResolveAsync(context, assertion, provider, cancellationToken);

        var result = await provider.AuthenticateAsync(assertion, credential, cancellationToken);
        if (unprotectFailed || result.Status is not (AuthenticationResultStatus.Succeeded or AuthenticationResultStatus.SucceededWithCredentialUpdate) || user == null)
        {
            return new AuthenticationResponse(false, Status: AuthenticationStatus.Failed);
        }

        if (!user.IsActive)
        {
            return new AuthenticationResponse(false, user, AuthenticationStatus.Disabled);
        }

        var status = result.Status == AuthenticationResultStatus.SucceededWithCredentialUpdate ? AuthenticationStatus.SuccessWithCredentialUpdate : AuthenticationStatus.Success;

        if (credential == null)
        {
            return new AuthenticationResponse(true, user, status, result.Claims);
        }

        try
        {
            var credentialUsageUpdated = await _credentialService.UpdateCredentialUsageAsync(credential, originalCredential, result, provider, cancellationToken);
            if (!credentialUsageUpdated)
            {
                return new AuthenticationResponse(false, user);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // TODO: Emit telemetry for non-critical credential lifecycle failures once logging is introduced.
            if (result.IsCredentialConsumed)
            {
                // Fail authentication if we cannot guarantee the credential was consumed (prevent replay/race conditions).
                return new AuthenticationResponse(false, user);
            }
        }

        return new AuthenticationResponse(true, user, status, result.Claims);
    }
}
