using Ashlar.Identity.Models;

namespace Ashlar.Identity.Abstractions;

public interface IBootstrapStateRepository
{
    Task<BootstrapStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default);
    Task<bool> MarkAsInitializedAsync(Guid userId, DateTimeOffset initializedAt, CancellationToken cancellationToken = default);
}
