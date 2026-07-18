namespace Ashlar.Tests.Identity.Features;

using Moq;
using Microsoft.Extensions.Time.Testing;

internal sealed class UserProfileServiceTests
{
    private readonly Mock<IUserRepository> _users = new();
    private readonly Mock<IAuthenticationSessionRepository> _sessions = new();
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 7, 18, 12, 0, 0, TimeSpan.Zero));
    private UserProfileService _service = null!;

    [SetUp]
    public void SetUp() => _service = new(_users.Object, _sessions.Object, _time);

    [Test]
    public async Task GetAsyncMapsUserAndMissingUser()
    {
        var user = User();
        _users.SetupSequence(repository => repository.GetUserByIdAsync(user.Id, default))
            .ReturnsAsync(user)
            .ReturnsAsync((IUser?)null);

        var profile = await _service.GetAsync(Session(user.Id));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(profile.Value, Is.EqualTo(new UserProfile(user.Id, user.DisplayEmail, user.Name)));
            Assert.That((await _service.GetAsync(Session(user.Id))).FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }
    }

    [Test]
    public async Task UpdateNameAsyncValidatesLengthAndUserExistence()
    {
        var userId = Guid.NewGuid();
        var tooLong = await _service.UpdateNameAsync(new(Session(userId), new string('x', 101), new(userId)));
        var missing = await _service.UpdateNameAsync(new(Session(userId), "name", new(userId)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tooLong.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missing.FailureDetails?.Code, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
        }
    }

    [Test]
    public async Task CurrentProfileUsesSessionBoundary()
    {
        var tenantId = Guid.NewGuid();
        var user = User() with { TenantId = tenantId };
        _users.Setup(repository => repository.GetUserByIdAsync(user.Id, default)).ReturnsAsync(user);

        var wrongActor = await _service.UpdateNameAsync(new(Session(user.Id, tenantId), "name", new(Guid.NewGuid())));
        var missingActor = await _service.UpdateNameAsync(new(Session(user.Id, tenantId), "name", new()));
        var wrongTenantRead = await _service.GetAsync(Session(user.Id, Guid.NewGuid()));
        var wrongTenant = await _service.UpdateNameAsync(new(Session(user.Id, Guid.NewGuid()), "name", new(user.Id)));
        var expiredRead = await _service.GetAsync(Session(user.Id, tenantId, _time.GetUtcNow()));
        var expiredUpdate = await _service.UpdateNameAsync(new(Session(user.Id, tenantId, _time.GetUtcNow()), "name", new(user.Id)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(wrongActor.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(missingActor.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(wrongTenantRead.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(wrongTenant.FailureCode, Is.EqualTo(AshlarFailureCodes.TenantMismatch));
            Assert.That(expiredRead.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
            Assert.That(expiredUpdate.FailureCode, Is.EqualTo(AshlarFailureCodes.SessionNotFoundOrInactive));
        }
    }

    [Test]
    public async Task CurrentProfileRejectsDisabledUserAndNullContext()
    {
        var user = User() with { AccountState = UserAccountState.Disabled };
        _users.Setup(repository => repository.GetUserByIdAsync(user.Id, default)).ReturnsAsync(user);

        var read = await _service.GetAsync(Session(user.Id));
        var update = await _service.UpdateNameAsync(new(Session(user.Id), "name", new(user.Id)));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(read.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
            Assert.That(update.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFoundOrUnavailable));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.GetAsync(null!));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateNameAsync(new(null!, "name", new(user.Id))));
            Assert.ThrowsAsync<ArgumentNullException>(() => _service.UpdateNameAsync(new(Session(user.Id), "name", null!)));
        }
    }

    [Test]
    public async Task CurrentProfileRejectsStaleOrMismatchedDurableSession()
    {
        var capability = Session(Guid.NewGuid(), Guid.NewGuid());
        _sessions.SetupSequence(repository => repository.GetSessionAsync(capability.Id, default))
            .ReturnsAsync((AuthenticationSession?)null)
            .ReturnsAsync(DurableSession(Guid.NewGuid(), capability.UserId, capability.TenantId))
            .ReturnsAsync(DurableSession(capability.Id, Guid.NewGuid(), capability.TenantId))
            .ReturnsAsync(DurableSession(capability.Id, capability.UserId, Guid.NewGuid()))
            .ReturnsAsync(DurableSession(capability.Id, capability.UserId, capability.TenantId, expiresAt: _time.GetUtcNow()))
            .ReturnsAsync(DurableSession(capability.Id, capability.UserId, capability.TenantId, revokedAt: _time.GetUtcNow()));

        var results = new List<Result<UserProfile>>();
        for (var index = 0; index < 6; index++) results.Add(await _service.GetAsync(capability));

        Assert.That(results.All(result => result.FailureCode == AshlarFailureCodes.SessionNotFoundOrInactive), Is.True);
    }

    [TestCase(null)]
    [TestCase("New name")]
    public async Task UpdateNameAsyncPersistsAndReturnsProfile(string? name)
    {
        var user = User();
        _users.Setup(repository => repository.GetUserByIdAsync(user.Id, default)).ReturnsAsync(user);

        var result = await _service.UpdateNameAsync(new(Session(user.Id), name, new(user.Id)));

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

    private ValidatedAuthenticationSession Session(Guid userId, Guid? tenantId = null, DateTimeOffset? expiresAt = null)
    {
        var session = new AuthenticationSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TenantId = tenantId,
            TokenHash = "hash",
            CreatedAt = _time.GetUtcNow(),
            ExpiresAt = expiresAt ?? _time.GetUtcNow().AddHours(1)
        };
        _sessions.Setup(repository => repository.GetSessionAsync(session.Id, default)).ReturnsAsync(session);
        return new(session);
    }

    private AuthenticationSession DurableSession(Guid id, Guid userId, Guid? tenantId, DateTimeOffset? expiresAt = null, DateTimeOffset? revokedAt = null) => new()
    {
        Id = id,
        UserId = userId,
        TenantId = tenantId,
        TokenHash = "hash",
        CreatedAt = _time.GetUtcNow(),
        ExpiresAt = expiresAt ?? _time.GetUtcNow().AddHours(1),
        RevokedAt = revokedAt
    };
}
