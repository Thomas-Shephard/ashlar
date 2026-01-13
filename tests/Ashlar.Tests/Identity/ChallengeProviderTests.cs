using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Moq;

namespace Ashlar.Tests.Identity;

public class ChallengeProviderTests
{
    private Mock<IIdentityRepository> _repositoryMock;
    private ChallengeProvider _provider;

    [SetUp]
    public void SetUp()
    {
        _repositoryMock = new Mock<IIdentityRepository>();
        _provider = new ChallengeProvider(_repositoryMock.Object);
    }

    [Test]
    public async Task GenerateChallengeAsyncShouldStoreChallengeInRepository()
    {
        var userId = Guid.NewGuid();
        var challenge = await _provider.GenerateChallengeAsync(userId);

        Assert.That(challenge.Length, Is.EqualTo(32));
        _repositoryMock.Verify(r => r.StoreChallengeAsync(
            challenge, 
            userId, 
            It.Is<DateTimeOffset>(d => d > DateTimeOffset.UtcNow), 
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task ValidateChallengeAsyncWithNullChallengeShouldReturnFalse()
    {
        var result = await _provider.ValidateChallengeAsync(null!);
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task ValidateChallengeAsyncWithEmptyChallengeShouldReturnFalse()
    {
        var result = await _provider.ValidateChallengeAsync(Array.Empty<byte>());
        Assert.That(result, Is.False);
    }

    [Test]
    public async Task ValidateChallengeAsyncShouldCallRepositoryConsume()
    {
        var challenge = new byte[32];
        var userId = Guid.NewGuid();
        _repositoryMock.Setup(r => r.ConsumeChallengeAsync(challenge, userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _provider.ValidateChallengeAsync(challenge, userId);

        Assert.That(result, Is.True);
        _repositoryMock.Verify(r => r.ConsumeChallengeAsync(challenge, userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void GetDummyChallengeShouldReturnStaticChallenge()
    {
        var challenge1 = _provider.GetDummyChallenge();
        var challenge2 = _provider.GetDummyChallenge();

        Assert.That(challenge1, Is.SameAs(challenge2));
        Assert.That(challenge1.Length, Is.EqualTo(32));
    }
}
