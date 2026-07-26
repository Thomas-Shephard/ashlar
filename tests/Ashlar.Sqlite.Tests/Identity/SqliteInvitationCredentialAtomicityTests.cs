using Ashlar.Identity.Abstractions.Services;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Ashlar.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace Ashlar.Sqlite.Tests.Identity;

internal sealed class SqliteInvitationCredentialAtomicityTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 3, 12, 0, 0, TimeSpan.Zero);

    private SqliteContractDatabase? _database;

    [TearDown]
    public void TearDown()
    {
        _database?.Delete();
        _database = null;
    }

    [Test]
    public async Task TenantInvitationWithoutContextShouldBeRejectedWithoutMutation()
    {
        const string token = "known-tenant-invitation-token";
        const string inviteeEmail = "tenant-invitee@example.com";
        var tenantId = Guid.NewGuid();

        _database = await SqliteContractDatabase.CreateAsync(ConfigureServices);
        await using var scope = _database.ServiceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        await SeedInvitationAsync(services, token, inviteeEmail, tenantId);

        var invitations = services.GetRequiredService<IInvitationService>();
        var preview = await invitations.GetInvitationAcceptancePreviewAsync(token);
        var acceptance = await invitations.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token });

        var tokenHash = services.GetRequiredService<ISecureTokenHasher>().HashToken(token);
        var storedInvitation = await services.GetRequiredService<IInvitationRepository>().GetInvitationByTokenHashAsync(tokenHash);
        var storedUser = await services.GetRequiredService<IUserRepository>().GetUserByEmailAsync(inviteeEmail, tenantId);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(preview.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidInvitation));
            Assert.That(acceptance.FailureCode, Is.EqualTo(AshlarFailureCodes.InvalidInvitation));
            Assert.That(storedInvitation?.AcceptedAt, Is.Null);
            Assert.That(storedUser, Is.Null);
        }
    }

    [Test]
    public async Task OuterTransactionShouldRollBackInvitationAcceptanceAndNewUserWhenOidcCredentialIsLinkedToAnotherUser()
    {
        const string token = "known-invitation-token";
        const string inviteeEmail = "invitee@example.com";
        const string existingEmail = "existing@example.com";
        const string subject = "oidc-subject";
        const string retrySubject = "oidc-retry-subject";
        var existingUserId = Guid.NewGuid();

        _database = await SqliteContractDatabase.CreateAsync(ConfigureServices);
        await using var scope = _database.ServiceProvider.CreateAsyncScope();
        var services = scope.ServiceProvider;

        await SeedInvitationAsync(services, token, inviteeEmail);
        await SeedExistingLinkedCredentialAsync(services, existingUserId, existingEmail, subject);

        var transactions = services.GetRequiredService<AshlarDurableTransactionProvider>();
        var invitations = services.GetRequiredService<IInvitationService>();
        var credentialRepository = services.GetRequiredService<ICredentialRepository>();
        await using (var transaction = await transactions.BeginTransactionAsync())
        {
            var acceptance = await invitations.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = "Invitee" });
            Assert.That(acceptance.Succeeded, Is.True);

            var link = await LinkCredentialForTestAsync(
                credentialRepository,
                acceptance.Value!.UserId,
                subject);

            Assert.That(link.FailureCode, Is.EqualTo(AshlarFailureCodes.AlreadyLinkedToOther));
            await transaction.RollbackAsync();
        }

        var invitationRepository = services.GetRequiredService<IInvitationRepository>();
        var userRepository = services.GetRequiredService<IUserRepository>();
        var rolledBackInvitation = await invitationRepository.GetInvitationByTokenHashAsync(services.GetRequiredService<ISecureTokenHasher>().HashToken(token));
        var rolledBackInvitee = await userRepository.GetUserByEmailAsync(inviteeEmail);

        Guid retryUserId;
        await using (var retryTransaction = await transactions.BeginTransactionAsync())
        {
            var retryAcceptance = await invitations.AcceptInvitationAsync(new AcceptInvitationRequest { Token = token, UserName = "Invitee" });
            Assert.That(retryAcceptance.Succeeded, Is.True);
            retryUserId = retryAcceptance.Value!.UserId;

            var retryLink = await LinkCredentialForTestAsync(
                credentialRepository,
                retryUserId,
                retrySubject);

            Assert.That(retryLink.Succeeded, Is.True);
            await retryTransaction.CommitAsync();
        }

        var invitation = await invitationRepository.GetInvitationByTokenHashAsync(services.GetRequiredService<ISecureTokenHasher>().HashToken(token));
        var invitee = await userRepository.GetUserByEmailAsync(inviteeEmail);
        var existingCredential = await credentialRepository.GetCredentialForUserAsync(existingUserId, ProviderType.Oidc, "Google", subject);
        var retryCredential = await credentialRepository.GetCredentialForUserAsync(retryUserId, ProviderType.Oidc, "Google", retrySubject);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rolledBackInvitation, Is.Not.Null);
            Assert.That(rolledBackInvitation!.AcceptedAt, Is.Null);
            Assert.That(rolledBackInvitee, Is.Null);
            Assert.That(invitation, Is.Not.Null);
            Assert.That(invitation!.AcceptedAt, Is.Not.Null);
            Assert.That(invitee, Is.Not.Null);
            Assert.That(existingCredential, Is.Not.Null);
            Assert.That(retryCredential, Is.Not.Null);
        }
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddAshlarInvitations();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<ISecretProtector, TestSecretProtector>();
        services.Replace(ServiceDescriptor.Singleton<IEmailSender, NullEmailSender>());
    }

    private static async Task SeedInvitationAsync(IServiceProvider services, string token, string email, Guid? tenantId = null)
    {
        await services.GetRequiredService<IInvitationRepository>().CreateInvitationAsync(new UserInvitation
        {
            Id = Guid.NewGuid(),
            DisplayEmail = email,
            TenantId = tenantId,
            TokenHash = services.GetRequiredService<ISecureTokenHasher>().HashToken(token),
            CreatedAt = Now,
            UpdatedAt = Now,
            ExpiresAt = Now.AddDays(1),
            Version = Guid.NewGuid().ToString("N")
        });
    }

    private static async Task SeedExistingLinkedCredentialAsync(IServiceProvider services, Guid userId, string email, string subject)
    {
        await services.GetRequiredService<IUserRepository>().CreateUserAsync(new AshlarUser
        {
            Id = userId,
            DisplayEmail = email,
            AccountState = UserAccountState.Active,
            EmailVerifiedAt = Now
        });
        await services.GetRequiredService<ICredentialRepository>().CreateCredentialAsync(new UserCredential
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            ProviderType = ProviderType.Oidc,
            ProviderName = "Google",
            ProviderKey = subject,
            Version = Guid.NewGuid().ToString("N"),
            CreatedAt = Now,
            Status = CredentialStatus.Active
        });
    }

    private static async Task<Result> LinkCredentialForTestAsync(
        ICredentialRepository credentialRepository,
        Guid userId,
        string providerKey)
    {
        try
        {
            await credentialRepository.CreateOrReplaceCredentialAsync(new UserCredential
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ProviderType = ProviderType.Oidc,
                ProviderName = "Google",
                ProviderKey = providerKey,
                Version = Guid.NewGuid().ToString("N"),
                CreatedAt = Now,
                Status = CredentialStatus.Active
            });
            return Result.Success();
        }
        catch (CredentialProviderKeyConflictException)
        {
            return Result.Failure(AshlarFailureCodes.AlreadyLinkedToOther);
        }
    }

    private sealed class TestSecretProtector : ISecretProtector
    {
        public string Protect(string plaintext) => plaintext;

        public string Unprotect(string protectedValue) => protectedValue;

        public byte[] Protect(byte[] plaintext) => plaintext;

        public byte[] Unprotect(byte[] protectedValue) => protectedValue;
    }
}
