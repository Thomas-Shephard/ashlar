using Microsoft.Extensions.DependencyInjection;

namespace Ashlar.Operational.Configuration;

internal sealed class AshlarConfigurationValidator(
    IServiceProvider serviceProvider,
    IEnumerable<IAshlarConfigurationCheck> checks)
    : IAshlarConfigurationValidator
{
    private readonly IServiceProvider _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    private readonly IEnumerable<IAshlarConfigurationCheck> _checks = checks ?? throw new ArgumentNullException(nameof(checks));

    public async Task<AshlarConfigurationValidationResult> ValidateAsync(CancellationToken cancellationToken = default)
    {
        List<AshlarConfigurationIssue> issues = [];

        await using var scope = _serviceProvider.CreateAsyncScope();
        foreach (var check in _checks)
        {
            cancellationToken.ThrowIfCancellationRequested();
            issues.AddRange(await check.CheckAsync(scope.ServiceProvider, cancellationToken));
        }

        return new AshlarConfigurationValidationResult(issues);
    }
}
