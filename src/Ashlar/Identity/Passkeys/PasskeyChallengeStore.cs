using Ashlar.Identity.Models.Passkeys;

namespace Ashlar.Identity.Passkeys;

internal sealed class PasskeyChallengeStore(IPasskeyChallengeRepository challenges) : IPasskeyChallengeStore
{
    public Task CreateAsync(PasskeyChallenge challenge, CancellationToken cancellationToken = default) => challenges.CreateAsync(challenge, cancellationToken);
    public Task<PasskeyChallenge?> GetAsync(Guid id, CancellationToken cancellationToken = default) => challenges.GetAsync(id, cancellationToken);
    public Task<bool> ConsumeAsync(Guid id, string expectedVersion, DateTimeOffset consumedAt, CancellationToken cancellationToken = default) => challenges.ConsumeAsync(id, expectedVersion, consumedAt, cancellationToken);
}
