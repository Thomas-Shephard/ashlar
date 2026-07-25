using Ashlar.Auditing;

namespace Ashlar.Tests.Identity.Features.Administration;

internal sealed class AccountRecoveryAdministrationServiceTests
{
    [Test]
    public void ConstructorRejectsNullDependency()
    {
        Assert.Throws<ArgumentNullException>(() => new AccountRecoveryAdministrationService(null!));
    }

    [Test]
    public void GetAccountRecoveryOptionsAsyncRejectsNullRequest()
    {
        var service = CreateService();

        Assert.ThrowsAsync<ArgumentNullException>(async () => await service.GetAccountRecoveryOptionsAsync(null!));
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncRejectsInvalidScopeAndUserId()
    {
        var service = CreateService();

        var missingScope = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(Guid.NewGuid()));
        var conflictingScope = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(Guid.NewGuid(), TenantContext.Global, IncludeAllTenants: true));
        var emptyUserId = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(Guid.Empty, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(missingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(conflictingScope.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
            Assert.That(emptyUserId.FailureCode, Is.EqualTo(AshlarFailureCodes.ValidationError));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncReturnsMissingUserFailure()
    {
        var service = CreateService(Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.UserNotFound));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(Guid.NewGuid(), TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncReturnsTenantMismatchFailure()
    {
        var service = CreateService(Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.UserNotFound, "User was not found in the requested tenant scope."));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(Guid.NewGuid(), new TenantContext(Guid.NewGuid())));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncMapsNullDetailValueToUserNotFound()
    {
        var service = CreateService(new Result<UserAdministrationDetail>(true));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(Guid.NewGuid(), TenantContext.Global));

        Assert.That(result.FailureCode, Is.EqualTo(AshlarFailureCodes.UserNotFound));
    }

    [TestCase(UserAccountState.Active, true)]
    [TestCase(UserAccountState.Disabled, false)]
    [TestCase(UserAccountState.Locked, false)]
    public async Task GetAccountRecoveryOptionsAsyncExposesAccountStateAndSignInAvailability(UserAccountState state, bool canSignIn)
    {
        var userId = Guid.NewGuid();
        var detail = CreateDetail(userId, posture: CreatePosture(userId, accountState: state, canSignIn: canSignIn));
        var service = CreateService(Result.Success(detail));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Value?.Detail.User, Is.SameAs(detail.User));
            Assert.That(result.Value?.Detail.SecurityPosture.AccountState, Is.EqualTo(state));
            Assert.That(result.Value?.Detail.SecurityPosture.CanSignIn, Is.EqualTo(canSignIn));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncPreservesGlobalTenantScope()
    {
        var userId = Guid.NewGuid();
        var userAdministration = new RecordingUserAdministrationService(Result.Success(CreateDetail(userId)));
        var service = CreateService(userAdministration: userAdministration);
        var eventWindow = TimeSpan.FromDays(3);
        var actor = CreateActor();

        await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global, RecentSecurityEventWindow: eventWindow, Actor: actor));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(userAdministration.LastRequest?.Tenant, Is.EqualTo(TenantContext.Global));
            Assert.That(userAdministration.LastRequest?.IncludeAllTenants, Is.False);
            Assert.That(userAdministration.LastRequest?.RecentSecurityEventWindow, Is.EqualTo(eventWindow));
            Assert.That(userAdministration.LastRequest?.Actor, Is.SameAs(actor));
        }
    }

    private static AccountSecurityActorContext CreateActor()
    {
        var userId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        return new AccountSecurityActorContext(userId, TenantContext.Global, sessionId,
            new FreshMfaVerificationProof(userId, null, sessionId, now, now.AddMinutes(5), AccountSecurityOperationBoundary.ProofPurpose),
            new AuditContext(userId));
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncPreservesIncludeAllTenantsScope()
    {
        var userId = Guid.NewGuid();
        var userAdministration = new RecordingUserAdministrationService(Result.Success(CreateDetail(userId, Guid.NewGuid())));
        var service = CreateService(userAdministration: userAdministration);

        await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(userAdministration.LastRequest?.Tenant, Is.Null);
            Assert.That(userAdministration.LastRequest?.IncludeAllTenants, Is.True);
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncReportsNoSessionOrMfaActionsWhenNothingConfigured()
    {
        var userId = Guid.NewGuid();
        var service = CreateService(Result.Success(CreateDetail(userId, posture: CreatePosture(userId))));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Detail.SecurityPosture.ActiveSessionCount, Is.Zero);
            Assert.That(result.Value?.Actions.WouldRevokeSessions, Is.False);
            Assert.That(result.Value?.Actions.WouldResetMfa, Is.False);
            Assert.That(result.Value?.Detail.SecurityPosture.AdditionalVerificationFactors, Is.Empty);
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncReportsActiveSessionsAndMfaFactors()
    {
        var userId = Guid.NewGuid();
        var posture = CreatePosture(
            userId,
            activeSessionCount: 2,
            additionalVerificationFactors:
            [
                new AdditionalVerificationFactorPosture(AuthenticationFactorTypes.Totp, "Authenticator app", true, true, [new AuthenticationProviderKey(ProviderType.Mfa, "totp")]),
                new AdditionalVerificationFactorPosture(AuthenticationFactorTypes.Passkey, "Passkey", true, false, [new AuthenticationProviderKey(ProviderType.Passkey, "passkey")]),
                new AdditionalVerificationFactorPosture("sms", "SMS", false, false, [])
            ],
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(new AuthenticationProviderKey(ProviderType.Mfa, "totp"), "Authenticator app", CredentialPosturePurpose.AdditionalVerification, factorType: AuthenticationFactorTypes.Totp, isAdditionalVerification: true, isResettable: true)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Detail.SecurityPosture.ActiveSessionCount, Is.EqualTo(2));
            Assert.That(result.Value?.Actions.WouldRevokeSessions, Is.True);
            Assert.That(result.Value?.Actions.WouldResetMfa, Is.True);
            Assert.That(result.Value?.Detail.SecurityPosture.AdditionalVerificationFactors, Has.Count.EqualTo(3));
            Assert.That(result.Value?.Detail.SecurityPosture.AdditionalVerificationFactors[0].FactorType, Is.EqualTo(AuthenticationFactorTypes.Totp));
            Assert.That(result.Value?.Detail.SecurityPosture.AdditionalVerificationFactors[1].FactorType, Is.EqualTo(AuthenticationFactorTypes.Passkey));
            Assert.That(result.Value?.Detail.SecurityPosture.AdditionalVerificationFactors[0].IsUsable, Is.True);
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncIgnoresRevokedResettableMfaCredentialsForResetPreview()
    {
        var userId = Guid.NewGuid();
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(new AuthenticationProviderKey(ProviderType.Mfa, "totp"), "Authenticator app", CredentialPosturePurpose.AdditionalVerification, factorType: AuthenticationFactorTypes.Totp, isAdditionalVerification: true, isResettable: true, status: CredentialStatus.Revoked)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Actions.WouldResetMfa, Is.False);
            Assert.That(result.Value?.Actions.RevocableProviderOptions.Select(option => option.Provider), Does.Not.Contain(new AuthenticationProviderKey(ProviderType.Mfa, "totp")));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncReportsMfaResetWhenRememberedMfaDevicesExist()
    {
        var userId = Guid.NewGuid();
        var tenant = new TenantContext(Guid.NewGuid());
        var rememberedMfaDevices = new RecordingRememberedMfaDeviceService
        {
            Devices =
            [
                new RememberedMfaDeviceSummary(Guid.NewGuid(), userId, tenant.TenantId, "Laptop", DateTimeOffset.UtcNow, null, DateTimeOffset.UtcNow.AddDays(30), null, null, true)
            ]
        };
        var service = CreateService(
            Result.Success(CreateDetail(userId, tenant.TenantId, CreatePosture(userId))),
            rememberedMfaDeviceService: rememberedMfaDevices);

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, tenant));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Actions.WouldResetMfa, Is.True);
            Assert.That(rememberedMfaDevices.LastUserId, Is.EqualTo(userId));
            Assert.That(rememberedMfaDevices.LastRequest?.Tenant, Is.EqualTo(tenant));
            Assert.That(rememberedMfaDevices.LastRequest?.ActiveOnly, Is.True);
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncUsesUnrestrictedRememberedMfaDeviceScopeWhenIncludingAllTenants()
    {
        var userId = Guid.NewGuid();
        var rememberedMfaDevices = new RecordingRememberedMfaDeviceService();
        var service = CreateService(
            Result.Success(CreateDetail(userId, Guid.NewGuid(), CreatePosture(userId))),
            rememberedMfaDeviceService: rememberedMfaDevices);

        await service.GetAccountRecoveryOptionsAsync(
            new AccountRecoveryOptionsRequest(userId, IncludeAllTenants: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(rememberedMfaDevices.LastRequest?.Tenant, Is.Null);
            Assert.That(rememberedMfaDevices.LastRequest?.IncludeAllTenants, Is.True);
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncPreservesSecurityPosturePrimaryCredentials()
    {
        var userId = Guid.NewGuid();
        var google = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(google, "Google", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(google, "Google", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(new AuthenticationProviderKey(ProviderType.Oidc, "Expired"), "Expired", CredentialPosturePurpose.Primary, isPrimary: true, isAvailable: false)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Detail.SecurityPosture.PrimaryCredentials, Has.Count.EqualTo(4));
            Assert.That(result.Value?.Detail.SecurityPosture.PrimaryCredentials.Select(credential => credential.Provider), Does.Contain(AuthenticationProviderKey.Local));
            Assert.That(result.Value?.Detail.SecurityPosture.PrimaryCredentials.Select(credential => credential.Provider), Does.Contain(google));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncBuildsRevocableProviderOptions()
    {
        var userId = Guid.NewGuid();
        var google = new AuthenticationProviderKey(ProviderType.Oidc, "Google");
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(google, "Google", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(google, "Google MFA", CredentialPosturePurpose.AdditionalVerification, factorType: AuthenticationFactorTypes.Passkey, isPrimary: false, isAdditionalVerification: true),
                CreateCredential(new AuthenticationProviderKey(ProviderType.Oidc, "NotRevocable"), "Not revocable", CredentialPosturePurpose.Primary, isPrimary: true, isRevocable: false)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Actions.RevocableProviderOptions, Has.Count.EqualTo(2));
            Assert.That(result.Value?.Actions.RevocableProviderOptions[0].Provider, Is.EqualTo(AuthenticationProviderKey.Local));
            Assert.That(result.Value?.Actions.RevocableProviderOptions[0].PrimaryCredentialCount, Is.EqualTo(1));
            Assert.That(result.Value?.Actions.RevocableProviderOptions[1].Provider, Is.EqualTo(google));
            Assert.That(result.Value?.Actions.RevocableProviderOptions[1].CredentialCount, Is.EqualTo(2));
            Assert.That(result.Value?.Actions.RevocableProviderOptions[1].AdditionalVerificationCredentialCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncFallsBackToProviderNameForBlankCredentialDisplayName()
    {
        var userId = Guid.NewGuid();
        var provider = new AuthenticationProviderKey(ProviderType.Oidc, "ExampleProvider");
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(provider, " ", CredentialPosturePurpose.Primary, isPrimary: true)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Actions.RevocableProviderOptions.Single().DisplayName, Is.EqualTo("ExampleProvider"));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncWarnsWhenProviderMayRemoveLastPrimarySignInMethod()
    {
        var userId = Guid.NewGuid();
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(new AuthenticationProviderKey(ProviderType.Mfa, "totp"), "Authenticator app", CredentialPosturePurpose.AdditionalVerification, factorType: AuthenticationFactorTypes.Totp, isAdditionalVerification: true)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            var localOption = result.Value?.Actions.RevocableProviderOptions.Single(option => option.Provider == AuthenticationProviderKey.Local);
            Assert.That(localOption?.WouldRemoveLastPrimarySignInMethod, Is.True);
            Assert.That(result.Value?.Actions.Warnings.Single().Code, Is.EqualTo(AccountRecoveryAdministrationService.LastPrimarySignInMethodWarningCode));
            Assert.That(result.Value?.Actions.Warnings.Single().Provider, Is.EqualTo(AuthenticationProviderKey.Local));
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncDoesNotWarnWhenAnotherPrimaryMethodRemains()
    {
        var userId = Guid.NewGuid();
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true),
                CreateCredential(new AuthenticationProviderKey(ProviderType.Oidc, "Google"), "Google", CredentialPosturePurpose.Primary, isPrimary: true)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        Assert.That(result.Value?.Actions.Warnings, Is.Empty);
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncDoesNotWarnForRevokedPrimaryCredential()
    {
        var userId = Guid.NewGuid();
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true, status: CredentialStatus.Revoked)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Actions.RevocableProviderOptions, Is.Empty);
            Assert.That(result.Value?.Actions.Warnings, Is.Empty);
        }
    }

    [Test]
    public async Task GetAccountRecoveryOptionsAsyncDoesNotWarnForUnavailablePrimaryCredential()
    {
        var userId = Guid.NewGuid();
        var posture = CreatePosture(
            userId,
            credentials:
            [
                CreateCredential(AuthenticationProviderKey.Local, "Password", CredentialPosturePurpose.Primary, isPrimary: true, isAvailable: false)
            ]);
        var service = CreateService(Result.Success(CreateDetail(userId, posture: posture)));

        var result = await service.GetAccountRecoveryOptionsAsync(new AccountRecoveryOptionsRequest(userId, TenantContext.Global));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Value?.Actions.RevocableProviderOptions.Single().WouldRemoveLastPrimarySignInMethod, Is.False);
            Assert.That(result.Value?.Actions.Warnings, Is.Empty);
        }
    }

    private static AccountRecoveryAdministrationService CreateService(
        Result<UserAdministrationDetail>? detailResult = null,
        RecordingUserAdministrationService? userAdministration = null,
        RecordingRememberedMfaDeviceService? rememberedMfaDeviceService = null)
    {
        return new AccountRecoveryAdministrationService(
            userAdministration ?? new RecordingUserAdministrationService(detailResult ?? Result.Failure<UserAdministrationDetail>(AshlarFailureCodes.UserNotFound)),
            rememberedMfaDeviceService);
    }

    private static UserAdministrationDetail CreateDetail(Guid userId, Guid? tenantId = null, AccountSecurityPosture? posture = null)
    {
        return new UserAdministrationDetail(
            new UserSummary(userId, "admin@example.com", "Admin User", tenantId, posture?.AccountState ?? UserAccountState.Active, posture?.CanSignIn ?? true, true, DateTimeOffset.UtcNow, null),
            posture ?? CreatePosture(userId));
    }

    private static AccountSecurityPosture CreatePosture(
        Guid userId,
        UserAccountState accountState = UserAccountState.Active,
        bool canSignIn = true,
        int activeSessionCount = 0,
        IReadOnlyList<AdditionalVerificationFactorPosture>? additionalVerificationFactors = null,
        IReadOnlyList<CredentialPostureItem>? credentials = null)
    {
        var credentialInventory = credentials ?? [];

        return new AccountSecurityPosture(
            userId,
            accountState,
            true,
            canSignIn,
            credentialInventory.Where(credential => credential.IsPrimaryCredential).ToArray(),
            additionalVerificationFactors ?? [],
            new AccountSecurityPolicyPosture(false, [], [], false, true, [], [], false),
            credentialInventory,
            activeSessionCount,
            null);
    }

    private static CredentialPostureItem CreateCredential(
        AuthenticationProviderKey provider,
        string displayName,
        CredentialPosturePurpose purpose,
        string? factorType = null,
        bool isPrimary = false,
        bool isAdditionalVerification = false,
        bool isAvailable = true,
        bool isRevocable = true,
        bool isResettable = false,
        CredentialStatus status = CredentialStatus.Active)
    {
        return new CredentialPostureItem(
            Guid.NewGuid(),
            provider,
            displayName,
            purpose,
            factorType,
            isPrimary,
            isAdditionalVerification,
            isAvailable,
            isRevocable,
            isResettable,
            DateTimeOffset.UtcNow,
            null,
            null,
            status);
    }

    private sealed class RecordingUserAdministrationService(Result<UserAdministrationDetail> detailResult) : IUserAdministrationService
    {
        public UserAdministrationDetailRequest? LastRequest { get; private set; }

        public Task<Result<UserSearchResult>> SearchUsersAsync(SearchUsersRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<Result<UserAdministrationDetail>> GetUserDetailAsync(UserAdministrationDetailRequest request, CancellationToken cancellationToken = default)
        {
            LastRequest = request;
            return Task.FromResult(detailResult);
        }
    }

    private sealed class RecordingRememberedMfaDeviceService : IRememberedMfaDeviceReader
    {
        public IReadOnlyList<RememberedMfaDeviceSummary> Devices { get; init; } = [];
        public Guid LastUserId { get; private set; }
        public ListRememberedMfaDevicesRequest? LastRequest { get; private set; }

        public Task<Result<RememberedMfaDeviceCreated>> CreateAfterSuccessfulMfaAsync(MfaAuthenticationResult mfaResult, CreateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<ValidateRememberedMfaDeviceResult> ValidateAsync(Guid userId, ValidateRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<RememberedMfaDeviceSummary>> ListAsync(Guid userId, ListRememberedMfaDevicesRequest request, CancellationToken cancellationToken = default)
        {
            LastUserId = userId;
            LastRequest = request;
            return Task.FromResult(Devices);
        }

        public Task<bool> RevokeCurrentAsync(RevokeCurrentRememberedMfaDeviceRequest request, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }
}
