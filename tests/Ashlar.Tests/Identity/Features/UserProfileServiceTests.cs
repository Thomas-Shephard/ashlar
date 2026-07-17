namespace Ashlar.Tests.Identity.Features;

using Moq;

internal sealed class UserProfileServiceTests
{
    private readonly Mock<IUserRepository> _users = new();
    private UserProfileService _service = null!;

    [SetUp]
    public void SetUp() => _service = new(_users.Object);

    [Test]
    public async Task GetAsyncMapsUserAndMissingUser()
    {
        var user = User();
        _users.SetupSequence(repository => repository.GetUserByIdAsync(user.Id, default))
            .ReturnsAsync(user)
            .ReturnsAsync((IUser?)null);

        var profile = await _service.GetAsync(user.Id);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile, Is.EqualTo(new UserProfile(user.Id, user.DisplayEmail, user.Name)));
            Assert.That(await _service.GetAsync(user.Id), Is.Null);
        }
    }

    [Test]
    public async Task UpdateNameAsyncValidatesLengthAndUserExistence()
    {
        var tooLong = await _service.UpdateNameAsync(Guid.NewGuid(), new string('x', 101));
        var missing = await _service.UpdateNameAsync(Guid.NewGuid(), "name");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tooLong.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missing.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.UserNotFound));
        }
    }

    [TestCase(null)]
    [TestCase("New name")]
    public async Task UpdateNameAsyncPersistsAndReturnsProfile(string? name)
    {
        var user = User();
        _users.Setup(repository => repository.GetUserByIdAsync(user.Id, default)).ReturnsAsync(user);

        var result = await _service.UpdateNameAsync(user.Id, name);

        Assert.That(result.Value, Is.EqualTo(new UserProfile(user.Id, user.DisplayEmail, name)));
        _users.Verify(repository => repository.UpdateUserAsync(
            It.Is<IUser>(updated => updated.Id == user.Id && updated.Name == name), default), Times.Once);
    }

    private static AshlarUser User() => new()
    {
        Id = Guid.NewGuid(),
        DisplayEmail = "user@example.test",
        Name = "Old name",
    };
}
