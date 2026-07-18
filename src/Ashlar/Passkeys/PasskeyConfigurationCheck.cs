using Ashlar.Operational.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Passkeys;

internal sealed class PasskeyConfigurationCheck : IAshlarConfigurationCheck
{
    public ValueTask<IReadOnlyList<AshlarConfigurationIssue>> CheckAsync(
        IServiceProvider serviceProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        cancellationToken.ThrowIfCancellationRequested();

        if (serviceProvider.GetService<AshlarProviderService<IPasskeyChallengeRepository>>() is not null)
            return ValueTask.FromResult<IReadOnlyList<AshlarConfigurationIssue>>([]);

        return ValueTask.FromResult<IReadOnlyList<AshlarConfigurationIssue>>(
        [
            new(
                AshlarConfigurationIssueCodes.PasskeyChallengeRepositoryMissing,
                AshlarConfigurationIssueSeverity.Error,
                "Passkey challenge persistence is not configured.",
                "Install and configure an Ashlar persistence provider with passkey challenge support.",
                "Passkeys"),
        ]);
    }
}
