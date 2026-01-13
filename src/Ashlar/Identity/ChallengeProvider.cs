using System.Security.Cryptography;
using Ashlar.Identity.Abstractions;

namespace Ashlar.Identity;

public sealed class ChallengeProvider : IChallengeProvider
{
    private readonly IIdentityRepository _repository;
    private static readonly byte[] DummyChallenge = new byte[32];

    static ChallengeProvider()
    {
        RandomNumberGenerator.Fill(DummyChallenge);
    }

    public ChallengeProvider(IIdentityRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    public async Task<byte[]> GenerateChallengeAsync(Guid? userId = null, CancellationToken cancellationToken = default)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        
        // Real Implementation: Store challenge in the repository with an expiration (5 minutes)
        await _repository.StoreChallengeAsync(challenge, userId, DateTimeOffset.UtcNow.AddMinutes(5), cancellationToken);
        
        return challenge;
    }

    public async Task<bool> ValidateChallengeAsync(byte[] challenge, Guid? userId = null, CancellationToken cancellationToken = default)
    {
        if (challenge == null || challenge.Length == 0)
        {
            return false;
        }

        // Real Implementation: Consume challenge from repository (atomic check-and-delete)
        return await _repository.ConsumeChallengeAsync(challenge, userId, cancellationToken);
    }

    public byte[] GetDummyChallenge() => DummyChallenge;
}