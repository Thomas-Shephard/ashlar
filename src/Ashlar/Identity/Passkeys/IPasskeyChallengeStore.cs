using Ashlar.Identity.Models.Passkeys;

namespace Ashlar.Identity.Passkeys;

internal interface IPasskeyChallengeStore
{
    Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default);
    Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default);
    Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
}
