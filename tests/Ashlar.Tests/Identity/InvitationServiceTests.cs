using System.Diagnostics.CodeAnalysis;
using Ashlar.Auditing;
using Ashlar.Identity;
using Ashlar.Identity.Abstractions;
using Ashlar.Identity.Models;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Ashlar.Tests.Identity;

internal sealed class InvitationServiceTests
{
    private readonly User _user = new() { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), Email = "existing@example.com", IsActive = true };

    [Test]
    public async Task CreateInvitationSendsEmailAndStoresHashedInvitation()
    {
        var fixture = CreateFixture();
        var request = new CreateInvitationRequest { Email = " invitee@example.com ", Metadata = "{\"role\":\"admin\"}" };
        var baseUri = new Uri("https://myapp.com/join");

        await fixture.Service.CreateInvitationAsync(request, baseUri);

        var message = fixture.EmailSender.Messages.First();
        var invitation = fixture.InvitationRepository.Invitations.First();

        Assert.That(message.To, Is.EqualTo("invitee@example.com"));
        var token = ExtractToken(message);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(invitation.Email, Is.EqualTo("invitee@example.com"));
            Assert.That(invitation.TokenHash, Is.EqualTo(fixture.TokenHasher.HashToken(token)));
            Assert.That(invitation.Metadata, Is.EqualTo("{\"role\":\"admin\"}"));
            Assert.That(invitation.ExpiresAt, Is.EqualTo(fixture.Time.GetUtcNow().AddDays(7)));
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.InvitationCreated), Is.True);
            Assert.That(GetProperties(fixture.Audit.Events.First(e => e.EventType == AshlarSecurityEventTypes.InvitationCreated))["email"], Is.EqualTo("INVITEE@EXAMPLE.COM"));
        }
    }

    [Test]
    public async Task CreateInvitationDoesNotLogEmailWhenStoreEmailInAuditIsDisabled()
    {
        var fixture = CreateFixture(configureOptions: options => options.StoreEmailInAudit = false);
        var request = new CreateInvitationRequest { Email = "invitee@example.com" };
        var baseUri = new Uri("https://myapp.com/join");

        await fixture.Service.CreateInvitationAsync(request, baseUri);

        var auditEvent = fixture.Audit.Events.First(e => e.EventType == AshlarSecurityEventTypes.InvitationCreated);
        Assert.That(GetProperties(auditEvent).ContainsKey("email"), Is.False);
    }

    [Test]
    public async Task CreateInvitationRevokesPreviousInvitationsForSameEmail()
    {
        var fixture = CreateFixture();
        var request = new CreateInvitationRequest { Email = "Invitee@Example.Com" };
        var baseUri = new Uri("https://myapp.com/join");

        await fixture.Service.CreateInvitationAsync(request, baseUri);
        await fixture.Service.CreateInvitationAsync(request, baseUri);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.InvitationRepository.Invitations, Has.Count.EqualTo(2));
            Assert.That(fixture.InvitationRepository.Invitations.Count(i => i.RevokedAt != null), Is.EqualTo(1));
            Assert.That(fixture.InvitationRepository.Invitations.Count(i => i.RevokedAt == null), Is.EqualTo(1));
        }
    }

    [Test]
    public async Task CreateInvitationRateLimitBlocksCreation()
    {
        var fixture = CreateFixture(creationAllowed: false);
        var request = new CreateInvitationRequest { Email = "invitee@example.com" };

        var result = await fixture.Service.CreateInvitationAsync(request, new Uri("https://myapp.com/join"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.InvitationRepository.Invitations, Is.Empty);
            Assert.That(fixture.Audit.Events.First().EventType, Is.EqualTo(AshlarSecurityEventTypes.InvitationRateLimited));
        }
    }

    [Test]
    public void CreateInvitationRejectsDisallowedCallbackBeforeGeneratingToken()
    {
        var fixture = CreateFixture(callbackAllowed: false);
        var request = new CreateInvitationRequest { Email = "invitee@example.com" };

        var ex = Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CreateInvitationAsync(request, new Uri("https://evil.example/join")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ex?.ParamName, Is.EqualTo("uri"));
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.InvitationRepository.Invitations, Is.Empty);
        }
    }

    [Test]
    public void CreateInvitationRejectsEmailWithLineBreaks()
    {
        var fixture = CreateFixture();
        var request = new CreateInvitationRequest { Email = "invitee@example.com\r\nBcc: attacker@example.com" };

        Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.CreateInvitationAsync(request, new Uri("https://myapp.com/join")));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.InvitationRepository.Invitations, Is.Empty);
        }
    }

    [Test]
    public async Task CreateInvitationUsesContextForRateLimit()
    {
        var fixture = CreateFixture();
        var request = new CreateInvitationRequest { Email = "test@example.com" };
        var context = new AuthenticationContext(IpAddress: "1.2.3.4", CorrelationId: "corr-123");

        await fixture.Service.CreateInvitationAsync(request, new Uri("https://myapp.com/join"), context);

        var rateLimitAttempt = fixture.RateLimiter.GetLastAttempt();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(rateLimitAttempt.Key, Is.EqualTo("invitation-create:TEST@EXAMPLE.COM"));
            Assert.That(rateLimitAttempt.IpAddress, Is.EqualTo("1.2.3.4"));
            Assert.That(rateLimitAttempt.CorrelationId, Is.EqualTo("corr-123"));
        }
    }

    [Test]
    public async Task AcceptInvitationCreatesNewUser()
    {
        var fixture = CreateFixture();
        var request = new CreateInvitationRequest { Email = "NewUser@Example.Com" };
        await fixture.Service.CreateInvitationAsync(request, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = "New User" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.Not.EqualTo(Guid.Empty));
            var user = fixture.IdentityRepository.Users.First(u => u.Email == "NewUser@Example.Com");
            Assert.That(user.Name, Is.EqualTo("New User"));
            Assert.That(user.IsActive, Is.True);
            Assert.That(fixture.InvitationRepository.Invitations.Any(i => i.AcceptedAt != null), Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.UserCreated), Is.True);
            Assert.That(fixture.Audit.Events.Any(e => e.EventType == AshlarSecurityEventTypes.InvitationAccepted), Is.True);
        }
    }

    [Test]
    public async Task AcceptInvitationCreatesVerifiedNewUserWhenConfigured()
    {
        var fixture = CreateFixture(configureOptions: options => options.VerifyEmailOnAcceptance = true);
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "NewUser@Example.Com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = "New User" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            var user = fixture.IdentityRepository.Users.First(u => u.Email == "NewUser@Example.Com");
            Assert.That(user.EmailVerifiedAt, Is.EqualTo(fixture.Time.GetUtcNow()));
        }
    }

    [Test]
    public async Task AcceptInvitationCreatesNewUserWithoutName()
    {
        var fixture = CreateFixture(configureOptions: options => options.VerifyEmailOnAcceptance = false);
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "NewUser@Example.Com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            var user = fixture.IdentityRepository.Users.First(u => u.Email == "NewUser@Example.Com");
            Assert.That(user.Name, Is.Null);
            Assert.That(user.EmailVerifiedAt, Is.Null);
        }
    }

    [Test]
    public async Task AcceptInvitationActivatesInactiveUser()
    {
        var inactiveUser = new User { Id = Guid.NewGuid(), Email = "INACTIVE@EXAMPLE.COM", IsActive = false, Name = "Old Name" };
        var fixture = CreateFixture(inactiveUser);
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "inactive@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = "Updated Name" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value, Is.EqualTo(inactiveUser.Id));
            var user = fixture.IdentityRepository.Users.First(u => u.Id == inactiveUser.Id);
            Assert.That(user.IsActive, Is.True);
            Assert.That(user.Name, Is.EqualTo("Updated Name"));
        }
    }

    [Test]
    public async Task CreateInvitationRejectsExistingActiveUser()
    {
        var fixture = CreateFixture(_user);

        var result = await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = _user.Email }, new Uri("https://myapp.com/join"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserExists));
            Assert.That(fixture.InvitationRepository.Invitations, Is.Empty);
            Assert.That(fixture.EmailSender.Messages, Is.Empty);
            Assert.That(fixture.Audit.Events.Any(e =>
                e.EventType == AshlarSecurityEventTypes.InvitationCreated &&
                e.Outcome == SecurityEventOutcomes.Failure &&
                e.FailureReason == "user_exists"), Is.True);
        }
    }

    [Test]
    public async Task AcceptInvitationActivatesInactiveUserWithoutVerifyingWhenDisabled()
    {
        var inactiveUser = new User { Id = Guid.NewGuid(), Email = "INACTIVE@EXAMPLE.COM", IsActive = false, Name = "Old Name" };
        var fixture = CreateFixture(inactiveUser, configureOptions: options => options.VerifyEmailOnAcceptance = false);
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "inactive@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = "Updated Name" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            var user = fixture.IdentityRepository.Users.First(u => u.Id == inactiveUser.Id);
            Assert.That(user.IsActive, Is.True);
            Assert.That(user.Name, Is.EqualTo("Updated Name"));
            Assert.That(user.EmailVerifiedAt, Is.Null);
        }
    }

    [Test]
    public async Task AcceptInvitationPreservesExistingVerificationTimestamp()
    {
        var verifiedAt = new DateTimeOffset(2026, 5, 1, 9, 0, 0, TimeSpan.Zero);
        var inactiveUser = new User { Id = Guid.NewGuid(), Email = "VERIFIED@EXAMPLE.COM", IsActive = false, Name = "Original Name", EmailVerifiedAt = verifiedAt };
        var fixture = CreateFixture(inactiveUser, configureOptions: options => options.VerifyEmailOnAcceptance = true);
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "verified@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            var user = fixture.IdentityRepository.Users.First(u => u.Id == inactiveUser.Id);
            Assert.That(user.IsActive, Is.True);
            Assert.That(user.EmailVerifiedAt, Is.EqualTo(verifiedAt));
        }
    }

    [Test]
    public async Task AcceptInvitationVerifiesExistingActiveUnverifiedUserWhenConfigured()
    {
        var activeUser = new User { Id = Guid.NewGuid(), Email = "ACTIVE@EXAMPLE.COM", IsActive = true, Name = "Active User" };
        var fixture = CreateFixture(activeUser, configureOptions: options => options.VerifyEmailOnAcceptance = true);
        fixture.InvitationRepository.Invitations.Add(new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "active@example.com",
            TokenHash = fixture.TokenHasher.HashToken("token"),
            CreatedAt = fixture.Time.GetUtcNow(),
            ExpiresAt = fixture.Time.GetUtcNow().AddDays(1),
            Version = "1"
        });

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = "token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            var user = fixture.IdentityRepository.Users.First(u => u.Id == activeUser.Id);
            Assert.That(user.IsActive, Is.True);
            Assert.That(user.EmailVerifiedAt, Is.EqualTo(fixture.Time.GetUtcNow()));
            Assert.That(fixture.IdentityRepository.UpdateCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task AcceptInvitationDoesNotUpdateExistingActiveUserWhenNoActivationOrVerificationIsNeeded()
    {
        var verifiedAt = new DateTimeOffset(2026, 5, 1, 9, 0, 0, TimeSpan.Zero);
        var activeUser = new User { Id = Guid.NewGuid(), Email = "ACTIVE@EXAMPLE.COM", IsActive = true, Name = "Active User", EmailVerifiedAt = verifiedAt };
        var fixture = CreateFixture(activeUser, configureOptions: options => options.VerifyEmailOnAcceptance = true);
        fixture.InvitationRepository.Invitations.Add(new UserInvitation
        {
            Id = Guid.NewGuid(),
            Email = "active@example.com",
            TokenHash = fixture.TokenHasher.HashToken("token"),
            CreatedAt = fixture.Time.GetUtcNow(),
            ExpiresAt = fixture.Time.GetUtcNow().AddDays(1),
            Version = "1"
        });

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = "token", UserName = "Ignored Name" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            var user = fixture.IdentityRepository.Users.First(u => u.Id == activeUser.Id);
            Assert.That(user.Name, Is.EqualTo("Active User"));
            Assert.That(user.EmailVerifiedAt, Is.EqualTo(verifiedAt));
            Assert.That(fixture.IdentityRepository.UpdateCount, Is.Zero);
        }
    }

    [Test]
    public async Task AcceptInvitationFailsForExpiredToken()
    {
        var fixture = CreateFixture();
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "test@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());
        fixture.Time.Advance(TimeSpan.FromDays(8));

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidInvitation));
        }
    }

    [Test]
    public async Task AcceptInvitationFailsForRevokedToken()
    {
        var fixture = CreateFixture();
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "test@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());
        await fixture.Service.RevokeInvitationsAsync("test@example.com");

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        Assert.That(result.Succeeded, Is.False);
    }

    [Test]
    public async Task AcceptInvitationRateLimitBlocksAcceptance()
    {
        var fixture = CreateFixture(acceptanceAllowed: false);
        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = "some-token" });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.RateLimited));
            Assert.That(fixture.Audit.Events.First().EventType, Is.EqualTo(AshlarSecurityEventTypes.InvitationRateLimited));
        }
    }

    [Test]
    public async Task RevokeInvitationsRecordsAuditEvent()
    {
        var fixture = CreateFixture();
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "test@example.com" }, new Uri("https://myapp.com/join"));

        fixture.Audit.Events.Clear();
        await fixture.Service.RevokeInvitationsAsync("test@example.com");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(fixture.InvitationRepository.Invitations.First().RevokedAt, Is.Not.Null);
            Assert.That(fixture.Audit.Events.First().EventType, Is.EqualTo(AshlarSecurityEventTypes.InvitationRevoked));
            Assert.That(GetProperties(fixture.Audit.Events.First())["count"], Is.EqualTo("1"));
        }
    }

    [Test]
    public void RevokeInvitationsRejectsEmailWithLineBreaks()
    {
        var fixture = CreateFixture();

        Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.RevokeInvitationsAsync("test@example.com\nCc: attacker@example.com"));
    }

    [Test]
    public void AddAshlarInvitationsResolvesService()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IIdentityRepository>());
        services.AddSingleton(Mock.Of<IInvitationRepository>());
        services.AddSingleton(Mock.Of<IAshlarTransactionProvider>());
        services.AddAshlarInvitations();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<IInvitationService>(), Is.TypeOf<InvitationService>());
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void ConstructorValidatesArguments()
    {
        var storeContext = new InvitationStoreContext(Mock.Of<IInvitationRepository>(), Mock.Of<IIdentityRepository>(), Mock.Of<IAshlarTransactionProvider>());
        var tokenContext = new SecureTokenContext(Mock.Of<ISecureTokenGenerator>(), Mock.Of<ISecureTokenHasher>());
        var infrastructure = new IdentityInfrastructureContext(Mock.Of<IEmailSender>(), Mock.Of<IAuthenticationRateLimiter>(), Mock.Of<IUriValidator>());
        var audit = new IdentityAuditContext(TimeProvider.System, Mock.Of<ISecurityEventSink>());

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationService(null!));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationStoreContext(null!, Mock.Of<IIdentityRepository>(), Mock.Of<IAshlarTransactionProvider>()));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationStoreContext(Mock.Of<IInvitationRepository>(), null!, Mock.Of<IAshlarTransactionProvider>()));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationStoreContext(Mock.Of<IInvitationRepository>(), Mock.Of<IIdentityRepository>(), null!));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationDependencies(null!, tokenContext, infrastructure, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationDependencies(storeContext, null!, infrastructure, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationDependencies(storeContext, tokenContext, null!, audit));
            Assert.Throws<ArgumentNullException>(() => _ = new InvitationDependencies(storeContext, tokenContext, infrastructure, null!));
        }
    }

    [Test]
    [SuppressMessage("ReSharper", "NullableWarningSuppressionIsUsed")]
    public void CreateInvitationValidatesArguments()
    {
        var fixture = CreateFixture();
        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.CreateInvitationAsync(null!, new Uri("https://myapp.com/join")));
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "test@example.com" }, null!));
        }
    }

    [Test]
    public void AcceptInvitationValidatesArguments()
    {
        var fixture = CreateFixture();
        using (Assert.EnterMultipleScope())
        {
            // ReSharper disable once NullableWarningSuppressionIsUsed
            Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Service.AcceptInvitationAsync(null!));
            Assert.ThrowsAsync<ArgumentException>(() => fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = " " }));
        }
    }

    [Test]
    public async Task AcceptInvitationFailsOnConcurrencyConflict()
    {
        var fixture = CreateFixture();
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "test@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        // Simulating conflict by making UpdateInvitationAsync return false
        fixture.InvitationRepository.SimulateConflict = true;

        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.ConcurrencyConflict));
    }

    [Test]
    public void AddAshlarInvitationsConfiguresOptions()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IIdentityRepository>());
        services.AddSingleton(Mock.Of<IInvitationRepository>());
        services.AddSingleton(Mock.Of<IAshlarTransactionProvider>());
        services.AddAshlarInvitations(options => options.EmailSubject = "Custom Subject");

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<InvitationOptions>>().Value;

        Assert.That(options.EmailSubject, Is.EqualTo("Custom Subject"));
    }

    [Test]
    public void ConstructorUsesDefaultsForOptionalArguments()
    {
        var service = new InvitationService(CreateDependencies(
            Mock.Of<IInvitationRepository>(),
            Mock.Of<IIdentityRepository>(),
            Mock.Of<ISecureTokenGenerator>(),
            Mock.Of<ISecureTokenHasher>(),
            Mock.Of<IEmailSender>(),
            Mock.Of<IAshlarTransactionProvider>(),
            Mock.Of<IAuthenticationRateLimiter>()));

        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task CreateInvitationUsesRequestExpiry()
    {
        var fixture = CreateFixture();
        var request = new CreateInvitationRequest { Email = "test@example.com", Expiry = TimeSpan.FromHours(1) };

        await fixture.Service.CreateInvitationAsync(request, new Uri("https://myapp.com/join"));

        var invitation = fixture.InvitationRepository.Invitations.First();
        Assert.That(invitation.ExpiresAt, Is.EqualTo(fixture.Time.GetUtcNow().AddHours(1)));
    }

    [Test]
    public async Task AcceptInvitationUsesExistingUserNameIfRequestNameIsNull()
    {
        var inactiveUser = new User { Id = Guid.NewGuid(), Email = "INACTIVE@EXAMPLE.COM", IsActive = false, Name = "Original Name" };
        var fixture = CreateFixture(inactiveUser);
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "inactive@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());

        await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = null });

        var user = fixture.IdentityRepository.Users.First(u => u.Id == inactiveUser.Id);
        Assert.That(user.Name, Is.EqualTo("Original Name"));
    }

    [Test]
    public void AddAshlarInvitationsWithNullConfigureWorks()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IIdentityRepository>());
        services.AddSingleton(Mock.Of<IInvitationRepository>());
        services.AddSingleton(Mock.Of<IAshlarTransactionProvider>());
        services.AddAshlarInvitations();

        using var provider = services.BuildServiceProvider();
        Assert.That(provider.GetRequiredService<IInvitationService>(), Is.Not.Null);
    }

    [Test]
    public async Task AcceptInvitationFailsForMissingInvitation()
    {
        var fixture = CreateFixture();
        var result = await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = "non-existent" });
        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidInvitation));
    }

    [Test]
    public async Task AcceptInvitationUsesContextForRateLimit()
    {
        var fixture = CreateFixture();
        await fixture.Service.CreateInvitationAsync(new CreateInvitationRequest { Email = "test@example.com" }, new Uri("https://myapp.com/join"));
        var token = ExtractToken(fixture.EmailSender.Messages.First());
        var context = new AuthenticationContext(IpAddress: "1.2.3.4", CorrelationId: "corr-123");

        await fixture.Service.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token }, context);

        var rateLimitAttempt = fixture.RateLimiter.GetLastAttempt();
        using (Assert.EnterMultipleScope())
        {
            Assert.That(rateLimitAttempt.Key, Is.EqualTo("invitation-accept:1.2.3.4"));
            Assert.That(rateLimitAttempt.IpAddress, Is.EqualTo("1.2.3.4"));
            Assert.That(rateLimitAttempt.CorrelationId, Is.EqualTo("corr-123"));
        }
    }

    private static Fixture CreateFixture(User? user = null, bool creationAllowed = true, bool acceptanceAllowed = true, Action<InvitationOptions>? configureOptions = null, bool callbackAllowed = true)
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 5, 3, 12, 0, 0, TimeSpan.Zero));
        var identityRepository = new InMemoryIdentityRepository(user);
        var invitationRepository = new InMemoryInvitationRepository(time);
        var audit = new RecordingSecurityEventSink();
        var emailSender = new RecordingEmailSender();
        var tokenHasher = new Sha256TokenHasher();
        var tokenGenerator = new SecureTokenGenerator();
        var transactionProvider = new NullTransactionProvider();
        var rateLimiter = new StubRateLimiter(creationAllowed, acceptanceAllowed, time);

        var options = new InvitationOptions();
        configureOptions?.Invoke(options);

        var service = new InvitationService(
            CreateDependencies(
                invitationRepository,
                identityRepository,
                tokenGenerator,
                tokenHasher,
                emailSender,
                transactionProvider,
                rateLimiter,
                audit,
                time,
                callbackAllowed),
            Options.Create(options));

        return new Fixture(service, invitationRepository, identityRepository, emailSender, audit, time, tokenHasher, rateLimiter);
    }

    private static string ExtractToken(EmailMessage message)
    {
        var body = message.TextBody;
        if (body == null)
        {
            throw new AssertionException("Expected invitation email to include a text body.");
        }

        return ExtractToken(body);
    }

    private static string ExtractToken(string body)
    {
        var parts = body.Split(' ');
        var url = parts.Last();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new AssertionException($"Invalid URL in email body: '{url}'. Body: '{body}'");
        }
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var token = query["t"];
        if (token == null)
        {
            throw new AssertionException($"Token 't' not found in query string: '{uri.Query}'. URL: '{url}'. Body: '{body}'");
        }
        return token;
    }

    private static IReadOnlyDictionary<string, string> GetProperties(AshlarSecurityEvent securityEvent)
    {
        if (securityEvent.Properties == null)
        {
            throw new AssertionException($"Expected security event '{securityEvent.EventType}' to include properties.");
        }

        return securityEvent.Properties;
    }

    private static InvitationDependencies CreateDependencies(
        IInvitationRepository invitationRepository,
        IIdentityRepository identityRepository,
        ISecureTokenGenerator tokenGenerator,
        ISecureTokenHasher tokenHasher,
        IEmailSender emailSender,
        IAshlarTransactionProvider transactionProvider,
        IAuthenticationRateLimiter rateLimiter,
        ISecurityEventSink? securityEventSink = null,
        TimeProvider? timeProvider = null,
        bool callbackAllowed = true)
    {
        var uriValidator = new Mock<IUriValidator>();
        if (!callbackAllowed)
        {
            uriValidator
                .Setup(v => v.ValidateOrThrow(It.IsAny<Uri?>()))
                .Throws((Uri? uri) => new ArgumentException("The URI is not allowed.", nameof(uri)));
        }

        return new InvitationDependencies(
            new InvitationStoreContext(invitationRepository, identityRepository, transactionProvider),
            new SecureTokenContext(tokenGenerator, tokenHasher),
            new IdentityInfrastructureContext(emailSender, rateLimiter, uriValidator.Object),
            new IdentityAuditContext(timeProvider ?? TimeProvider.System, securityEventSink ?? new NullSecurityEventSink()));
    }

    private sealed record Fixture(InvitationService Service, InMemoryInvitationRepository InvitationRepository, InMemoryIdentityRepository IdentityRepository, RecordingEmailSender EmailSender, RecordingSecurityEventSink Audit, FakeTimeProvider Time, ISecureTokenHasher TokenHasher, StubRateLimiter RateLimiter);

    private sealed class StubRateLimiter(bool creationAllowed, bool acceptanceAllowed, TimeProvider timeProvider) : IAuthenticationRateLimiter
    {
        private RateLimitAttempt? _lastAttempt;
        public RateLimitAttempt GetLastAttempt()
        {
            if (_lastAttempt == null)
            {
                throw new AssertionException("Expected rate limiter to have received an attempt.");
            }

            return _lastAttempt;
        }

        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            _lastAttempt = attempt;
            var allowed = attempt.Purpose == "invitation-create" ? creationAllowed : acceptanceAllowed;
            return Task.FromResult(new RateLimitDecision
            {
                Status = allowed ? RateLimitStatus.Allowed : RateLimitStatus.Blocked,
                Remaining = allowed ? 1 : 0,
                WindowResetAt = timeProvider.GetUtcNow().Add(rule.Window)
            });
        }
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<AshlarSecurityEvent> Events { get; } = [];
        public Task RecordAsync(AshlarSecurityEvent securityEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(securityEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryIdentityRepository(params User?[] users) : IIdentityRepository
    {
        public List<User> Users { get; } = users.OfType<User>().ToList();
        public int UpdateCount { get; private set; }
        public Task<IUser?> GetUserByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(Users.FirstOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)));
        public Task<IUser?> GetUserByIdAsync(Guid userId, CancellationToken cancellationToken = default) => Task.FromResult<IUser?>(Users.FirstOrDefault(u => u.Id == userId));
        public Task CreateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            if (Users.Any(u => u.Id == user.Id)) return Task.CompletedTask;
            Users.Add(new User
            {
                Id = user.Id,
                Email = user.Email,
                Name = user.Name,
                IsActive = user.IsActive,
                TenantId = (user as ITenantUser)?.TenantId,
                EmailVerifiedAt = user.EmailVerifiedAt
            });
            return Task.CompletedTask;
        }
        public Task UpdateUserAsync(IUser user, CancellationToken cancellationToken = default)
        {
            UpdateCount++;
            var existing = Users.FirstOrDefault(u => u.Id == user.Id);
            if (existing != null)
            {
                existing.Name = user.Name;
                existing.IsActive = user.IsActive;
                existing.EmailVerifiedAt = user.EmailVerifiedAt;
            }
            return Task.CompletedTask;
        }

        public Task<UserCredential?> GetCredentialForUserAsync(Guid userId, ProviderType type, string providerName, string? providerKey = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<IUser?> GetUserByProviderKeyAsync(ProviderType type, string providerName, string providerKey, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task CreateCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task CreateOrReplaceCredentialAsync(UserCredential credential, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> UpdateCredentialAsync(UserCredential credential, string expectedVersion, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<bool> ConsumeCredentialAsync(Guid credentialId, string expectedVersion, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public Task<int> RevokeCredentialsAsync(Guid userId, ProviderType type, string providerName, CancellationToken cancellationToken = default) => throw new NotImplementedException();
    }

    private sealed class InMemoryInvitationRepository(TimeProvider timeProvider) : IInvitationRepository
    {
        public List<UserInvitation> Invitations { get; } = [];
        public bool SimulateConflict { get; set; }

        public Task CreateInvitationAsync(UserInvitation invitation, CancellationToken cancellationToken = default)
        {
            Invitations.Add(invitation);
            return Task.CompletedTask;
        }

        public Task<UserInvitation?> GetInvitationByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Invitations.FirstOrDefault(i => i.TokenHash == tokenHash));
        }

        public Task<bool> UpdateInvitationAsync(UserInvitation invitation, string expectedVersion, CancellationToken cancellationToken = default)
        {
            if (SimulateConflict) return Task.FromResult(false);

            var existing = Invitations.FirstOrDefault(i => i.Id == invitation.Id && i.Version == expectedVersion);
            if (existing == null) return Task.FromResult(false);

            existing.AcceptedAt = invitation.AcceptedAt;
            existing.RevokedAt = invitation.RevokedAt;
            existing.Metadata = invitation.Metadata;
            existing.Version = Guid.NewGuid().ToString("N");
            invitation.Version = existing.Version;
            return Task.FromResult(true);
        }

        public Task<int> RevokeInvitationsByEmailAsync(string email, Guid? tenantId = null, CancellationToken cancellationToken = default)
        {
            var normalizedSearchEmail = IdentityNormalization.NormalizeEmail(email);
            var toRevoke = Invitations.Where(i => IdentityNormalization.NormalizeEmail(i.Email) == normalizedSearchEmail && i.TenantId == tenantId && i.AcceptedAt == null && i.RevokedAt == null).ToList();
            foreach (var i in toRevoke)
            {
                i.RevokedAt = timeProvider.GetUtcNow();
            }
            return Task.FromResult(toRevoke.Count);
        }
    }
}
