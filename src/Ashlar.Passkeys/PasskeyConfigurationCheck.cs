using Ashlar.Operational.Configuration;

namespace Ashlar.Passkeys;

internal sealed class PasskeyConfigurationCheck : IAshlarConfigurationCheck
{
    public ValueTask<IReadOnlyList<AshlarConfigurationIssue>> CheckAsync(
        IServiceProvider serviceProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        cancellationToken.ThrowIfCancellationRequested();

        if (serviceProvider.IsServiceRegistered<IPasskeyChallengeRepository>())
        {
            return ValueTask.FromResult<IReadOnlyList<AshlarConfigurationIssue>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<AshlarConfigurationIssue>>(
        [
            new(
                AshlarConfigurationIssueCodes.PasskeyChallengeRepositoryMissing,
                AshlarConfigurationIssueSeverity.Error,
                "Passkey challenge persistence is not configured.",
                "Register an IPasskeyChallengeRepository implementation before using Ashlar passkeys.",
                "Passkeys"),
        ]);
    }
}
