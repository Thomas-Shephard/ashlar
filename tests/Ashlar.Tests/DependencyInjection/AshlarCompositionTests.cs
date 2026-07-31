using Ashlar.Auditing;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
using Ashlar.Operational;
using Ashlar.Operational.Diagnostics;
using Ashlar.Security.Encryption;
using Ashlar.Testing.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;

namespace Ashlar.Tests.DependencyInjection;

internal sealed class AshlarCompositionTests
{
    [Test]
    public void DurableCompositionIsNotExposedThroughOrdinaryTransactionContract()
    {
        var services = new ServiceCollection();
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>("Test");
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetService<IAshlarTransactionProvider>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.Not.Null);
        }
    }

    [TestCase(false)]
    [TestCase(true)]
    public void SecurityEventFanOutUsesDurableCompositionInsteadOfOrdinaryTransactionAlias(bool authorization)
    {
        var services = new ServiceCollection();
        services.AddAshlarIdentity();
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>("Test");
        services.AddScoped<IAshlarTransactionProvider>(_ => new IndependentTransactionProvider());
        if (authorization) services.AddAshlarAuthorization();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<SecurityEventFanOutSink>().TransactionProvider,
            Is.SameAs(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>()));
    }

    [Test]
    public void CoreDurableParticipantRegistrationRejectsNullServices()
    {
        Assert.Throws<ArgumentNullException>(() => AshlarProviderServiceCollectionExtensions.AddAshlarIdentityDurableTransactionParticipants(null!));
        Assert.Throws<ArgumentNullException>(() =>
            AshlarProviderServiceCollectionExtensions.ReplaceAshlarOperationalAdministrationScoped<
                IndependentTransactionProvider, ICustomOperationalAdministrationService,
                CustomOperationalAdministrationService>(
                null!, "Custom", AshlarOperationalAdministrationKind.EmailOutbox));
    }

    [Test]
    public void ProviderResolverRequiresExplicitProviderRegistration()
    {
        var providerServices = new ServiceCollection();
        providerServices.AddAshlarProviderScoped(_ => new ScopedDependency());
        using var providerServiceProvider = providerServices.BuildServiceProvider();
        var ordinary = new ServiceCollection();
        ordinary.AddScoped<ScopedDependency>();
        using var ordinaryProvider = ordinary.BuildServiceProvider();

        Assert.That(Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<ScopedDependency>(providerServiceProvider), Is.Not.Null);
        Assert.Throws<InvalidOperationException>(() =>
            Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<ScopedDependency>(ordinaryProvider));
    }

    [Test]
    public void ProviderRegistrationRejectsNullServiceInstances()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped<ScopedDependency>(_ => null!);
        using var provider = services.BuildServiceProvider();

        Assert.Throws<ArgumentNullException>(() =>
            Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<ScopedDependency>(provider));
    }

    [Test]
    public void ProviderServicesDoNotExposeRawContractsThroughServiceDescriptors()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<ICredentialRepository>());

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IUserRepository)), Is.False);
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(ICredentialRepository)), Is.False);
            Assert.That(provider.GetService<IUserRepository>(), Is.Null);
            Assert.That(provider.GetService<ICredentialRepository>(), Is.Null);
            Assert.That(provider.GetKeyedService<IUserRepository>("ashlar-provider"), Is.Null);
            Assert.That(provider.GetKeyedService<ICredentialRepository>("ashlar-provider"), Is.Null);
            Assert.That(services.Where(descriptor => descriptor.ServiceKey is not null)
                .Select(descriptor => provider.GetKeyedService(typeof(IUserRepository), descriptor.ServiceKey!)), Is.All.Null);
            Assert.That(Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<IUserRepository>(provider), Is.Not.Null);
            Assert.That(Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<ICredentialRepository>(provider), Is.Not.Null);
        }
    }

    [Test]
    public void ProviderContractsExposeNoRuntimeProviderServiceResolver()
    {
        Assert.That(typeof(AshlarProviderServiceCollectionExtensions).GetMethods()
            .Any(method => method.IsPublic &&
                           method.Name == "GetRequiredAshlarProviderService"), Is.False);
    }

    [TestCase(AshlarOperationalAdministrationKind.EmailOutbox)]
    [TestCase(AshlarOperationalAdministrationKind.SecurityEventWebhookOutbox)]
    public void CustomProviderCanPublishOperationalAdministrationWithoutExposingRawDependencies(
        AshlarOperationalAdministrationKind kind)
    {
        var sessions = Mock.Of<IAuthenticationSessionRepository>();
        var auditSink = Mock.Of<IPersistentSecurityEventSink>();
        var ordinary = new ScopedDependency();
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped<IndependentTransactionProvider, IAuthenticationSessionRepository>(
            "Custom", _ => sessions);
        services.AddAshlarProviderScoped<IndependentTransactionProvider, IPersistentSecurityEventSink>(
            "Custom", _ => auditSink);
        services.AddScoped(_ => ordinary);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(Mock.Of<IAccountSecurityOperationAuthorizer>());
        services.ReplaceAshlarOperationalAdministrationScoped<IndependentTransactionProvider,
            ICustomOperationalAdministrationService, CustomOperationalAdministrationService>(
            "Custom", kind);

        using var provider = services.BuildServiceProvider();
        ICustomOperationalAdministrationService administration;
        using (var scope = provider.CreateScope())
        {
            administration = scope.ServiceProvider.GetRequiredService<ICustomOperationalAdministrationService>();

            using (Assert.EnterMultipleScope())
            {
                Assert.That(administration.Administration.ReadBoundary, Is.Not.Null);
                Assert.That(administration.Administration.MutationBoundary, Is.Not.Null);
                Assert.That(administration.Ordinary, Is.SameAs(ordinary));
                Assert.That(scope.ServiceProvider.GetService<IAuthenticationSessionRepository>(), Is.Null);
                Assert.That(scope.ServiceProvider.GetService<IPersistentSecurityEventSink>(), Is.Null);
                Assert.That(scope.ServiceProvider.GetKeyedService<IAuthenticationSessionRepository>("ashlar-provider"), Is.Null);
                Assert.That(scope.ServiceProvider.GetKeyedService<IPersistentSecurityEventSink>("ashlar-provider"), Is.Null);
                Assert.Throws<ArgumentNullException>(() => new AshlarOperationalAdministrationContext(
                    null!, administration.Administration.MutationBoundary));
                Assert.Throws<ArgumentNullException>(() => new AshlarOperationalAdministrationContext(
                    administration.Administration.ReadBoundary, null!));
            }
        }

        Assert.That(administration.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public void OperationalAdministrationRegistrationRejectsUnknownBoundaryKindOnResolution()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped<IndependentTransactionProvider, IAuthenticationSessionRepository>(
            "Custom", _ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarProviderScoped<IndependentTransactionProvider, IPersistentSecurityEventSink>(
            "Custom", _ => Mock.Of<IPersistentSecurityEventSink>());
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(Mock.Of<IAccountSecurityOperationAuthorizer>());
        services.AddScoped<ScopedDependency>();
        services.ReplaceAshlarOperationalAdministrationScoped<IndependentTransactionProvider,
            ICustomOperationalAdministrationService, CustomOperationalAdministrationService>(
            "Custom", (AshlarOperationalAdministrationKind)int.MaxValue);
        using var provider = services.BuildServiceProvider();

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            provider.GetRequiredService<ICustomOperationalAdministrationService>());
    }

    [Test]
    public async Task ProviderWrapperPreservesScopedResourceDisposal()
    {
        var sync = new DisposableDependency();
        var async = new AsyncDisposableDependency();
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => sync);
        services.AddAshlarProviderScoped(_ => async);
        services.AddAshlarProviderScoped(_ => new ScopedDependency());

        await using (var provider = services.BuildServiceProvider())
        await using (var scope = provider.CreateAsyncScope())
        {
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<DisposableDependency>(scope.ServiceProvider);
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<AsyncDisposableDependency>(scope.ServiceProvider);
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<ScopedDependency>(scope.ServiceProvider);
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sync.DisposeCount, Is.EqualTo(1));
            Assert.That(async.DisposeCount, Is.EqualTo(1));
        }
    }

    [Test]
    public void ProviderWrapperDisposesSyncResourceExactlyOnce()
    {
        var dependency = new DisposableDependency();
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => dependency);
        using var provider = services.BuildServiceProvider();
        using (var scope = provider.CreateScope())
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<DisposableDependency>(scope.ServiceProvider);

        Assert.That(dependency.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public void ProviderAliasLeavesDisposalToOrdinaryRegistration()
    {
        var dependency = new DisposableDependency();
        var services = new ServiceCollection();
        services.AddScoped(_ => dependency);
        services.AddAshlarDurableTransactionProvider<DisposableDependency>("Test", provider =>
            provider.GetRequiredService<DisposableDependency>());

        using (var provider = services.BuildServiceProvider())
        using (var scope = provider.CreateScope())
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<DisposableDependency>(scope.ServiceProvider);

        Assert.That(dependency.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public async Task ProviderAliasLeavesAsyncDisposalToOrdinaryRegistration()
    {
        var dependency = new AsyncDisposableDependency();
        var services = new ServiceCollection();
        services.AddScoped(_ => dependency);
        services.AddAshlarDurableTransactionProvider<AsyncDisposableDependency>("Test", provider =>
            provider.GetRequiredService<AsyncDisposableDependency>());

        await using (var provider = services.BuildServiceProvider())
        await using (var scope = provider.CreateAsyncScope())
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<AsyncDisposableDependency>(scope.ServiceProvider);

        Assert.That(dependency.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public void ProviderWrapperSynchronouslyDisposesAsyncOnlyResourceExactlyOnce()
    {
        var dependency = new AsyncDisposableDependency();
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => dependency);
        using var provider = services.BuildServiceProvider();
        using (var scope = provider.CreateScope())
            _ = Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<AsyncDisposableDependency>(scope.ServiceProvider);

        Assert.That(dependency.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public void OrdinaryRawRegistrationCannotReplaceProviderOwnedService()
    {
        var providerRepository = Mock.Of<IUserRepository>();
        var applicationRepository = Mock.Of<IUserRepository>();
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => providerRepository);
        services.AddScoped(_ => applicationRepository);

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(provider.GetRequiredService<IUserRepository>(), Is.SameAs(applicationRepository));
            Assert.That(Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<IUserRepository>(provider), Is.SameAs(providerRepository));
        }
    }

    [Test]
    public void ApplicationExtensionsExposeNoDurableSelfAttestationMethods()
    {
        var publicDurableMethods = typeof(AshlarServiceCollectionExtensions).GetMethods()
            .Where(method => method.IsPublic && method.Name.Contains("Durable", StringComparison.Ordinal));

        Assert.That(publicDurableMethods, Is.Empty);
    }

    [Test]
    public void SecurityEventFanOutExposesOnlyDurableTransactionComposition()
    {
        var transactionParameter = typeof(SecurityEventFanOutSink).GetConstructors().Single()
            .GetParameters().Single(parameter => parameter.Name == "transactionProvider");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(transactionParameter.ParameterType, Is.EqualTo(typeof(AshlarDurableTransactionProvider)));
            Assert.That(typeof(SecurityEventFanOutSink).GetProperty(nameof(SecurityEventFanOutSink.TransactionProvider))!.PropertyType,
                Is.EqualTo(typeof(AshlarDurableTransactionProvider)));
        }
    }

    [Test]
    public void AuthenticationProviderResolversExposeOnlyReadCapabilities()
    {
        var userParameter = typeof(IAuthenticationUserResolver).GetMethod(nameof(IAuthenticationUserResolver.FindUserAsync))!
            .GetParameters()[2].ParameterType;
        var credentialParameter = typeof(IAuthenticationCredentialResolver).GetMethod(nameof(IAuthenticationCredentialResolver.ResolveCredentialAsync))!
            .GetParameters()[3].ParameterType;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(userParameter, Is.EqualTo(typeof(IUserLookup)));
            Assert.That(credentialParameter, Is.EqualTo(typeof(ICredentialLookup)));
        }
    }

    [Test]
    public void FreshProofValidatorIsInternalAndNotRegistered()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetService<ActiveSessionFreshProofValidator>(), Is.Null);
            Assert.That(scope.ServiceProvider.GetService<IAuthenticationSessionRepository>(), Is.Null);
            Assert.That(typeof(ActiveSessionFreshProofValidator).IsNotPublic, Is.True);
        }
    }

    [Test]
    public void CoreIdentityCompositionBuildsWithStrictValidationAndRequiredTestDoubles()
    {
        var secretProtector = new RecordingSecretProtector();
        var emailSender = new RecordingEmailSender();
        var rateLimiter = new RecordingAuthenticationRateLimiter();
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<ICredentialRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserAdministrationRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<ICredentialAdministrationRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddSingleton<ISecretProtector>(secretProtector);
        services.AddSingleton<IEmailSender>(emailSender);
        services.AddSingleton<IAuthenticationRateLimiter>(rateLimiter);
        services.AddSingleton(Mock.Of<IAccountSecurityOperationAuthorizer>());
        services
            .AddAshlarIdentity()
            .AddDurableAuditForTests()
            .AddPermissiveAccountSecurityGuard()
            .AddAuthenticationProvider<LocalPasswordProvider>()
            .AddPasswordHasher<FakePasswordHasher>();

        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services,
            typeof(IIdentityService),
            typeof(IAuthenticationPipeline),
            typeof(ICredentialService),
            typeof(IUserAdministrationReader),
            typeof(ICredentialAdministrationReader),
            typeof(IAuthenticationSessionAdministrationReader),
            typeof(IdentityInfrastructureContext),
            typeof(AshlarDurableTransactionProvider),
            typeof(IAuthenticationRateLimiterDiagnostics),
            typeof(IAshlarOperationsSummaryService));
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecretProtector>(), Is.SameAs(secretProtector));
            Assert.That(scope.ServiceProvider.GetRequiredService<IEmailSender>(), Is.SameAs(emailSender));
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.SameAs(rateLimiter));
            Assert.That(scope.ServiceProvider.GetRequiredService<IUserAdministrationReader>(), Is.TypeOf<UserAdministrationReader>());
            Assert.That(scope.ServiceProvider.GetRequiredService<ICredentialAdministrationReader>(), Is.TypeOf<CredentialAdministrationReader>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationSessionAdministrationReader>(), Is.TypeOf<AuthenticationSessionAdministrationReader>());
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(Microsoft.Extensions.DependencyInjection.AshlarProviderServiceCollection.GetRequiredAshlarProviderService<RecordingTransactionProvider>(scope.ServiceProvider), Is.Not.Null);
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecurityEventSink>(), Is.TypeOf<SecurityEventFanOutSink>());
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarOperationsSummaryService>(), Is.TypeOf<AshlarOperationsSummaryService>());
            Assert.That(provider.GetServices<IHostedService>(), Is.Empty);
        }
    }

    [Test]
    public void ServiceProviderValidationBuildsStrictProviderAndResolvesExpectedServices()
    {
        using var provider = ServiceProviderValidation.BuildValidatedServiceProvider(
            services => services.AddScoped<ScopedDependency>(),
            typeof(ScopedDependency));

        using var scope = provider.CreateScope();

        Assert.That(scope.ServiceProvider.GetRequiredService<ScopedDependency>(), Is.Not.Null);
    }

    [Test]
    public async Task DurableProviderJoinsNestedCallsWithoutTrustingCustomProvider()
    {
        var raw = new IndependentTransactionProvider();
        var provider = AshlarDurableTransactionProvider.Create(raw);

        await using (var outer = await provider.BeginTransactionAsync())
        {
            await using (var inner = await provider.BeginTransactionAsync())
            {
                Assert.Throws<ArgumentNullException>(() => inner.OnCommitted(null!));
                inner.OnCommitted(_ => Task.CompletedTask);
                await inner.CommitAsync();
                Assert.ThrowsAsync<InvalidOperationException>(() => inner.CommitAsync());
            }
            Assert.Throws<ArgumentNullException>(() => outer.OnCommitted(null!));
            await outer.CommitAsync();
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(raw.BeginCount, Is.EqualTo(1));
            Assert.That(raw.Transaction.CommitCount, Is.EqualTo(1));
            Assert.That(raw.Transaction.HookCount, Is.EqualTo(1));
        }

        await using (var rollbackOuter = await provider.BeginTransactionAsync())
        {
            await using (var inner = await provider.BeginTransactionAsync())
            {
                await inner.RollbackAsync();
            }

            using (Assert.EnterMultipleScope())
            {
                Assert.That(raw.BeginCount, Is.EqualTo(2));
                var exception = Assert.ThrowsAsync<InvalidOperationException>(() => rollbackOuter.CommitAsync());
                Assert.That(exception!.InnerException?.Message, Is.EqualTo("A nested transaction explicitly called RollbackAsync."));
            }
            await rollbackOuter.RollbackAsync();
            Assert.That(raw.Transaction.RollbackCount, Is.EqualTo(1));
        }
    }

    [Test]
    public async Task DurableProviderCanRetryAfterCustomProviderBeginFails()
    {
        var raw = new IndependentTransactionProvider { FailNextBegin = true };
        var provider = AshlarDurableTransactionProvider.Create(raw);

        Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
        await using var transaction = await provider.BeginTransactionAsync();

        Assert.That(raw.BeginCount, Is.EqualTo(2));
    }

    [Test]
    public async Task DurableProviderCanRetryAfterCustomProviderReturnsNull()
    {
        var raw = new IndependentTransactionProvider { ReturnNull = true };
        var provider = AshlarDurableTransactionProvider.Create(raw);

        Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
        raw.ReturnNull = false;
        await using var transaction = await provider.BeginTransactionAsync();

        Assert.That(raw.BeginCount, Is.EqualTo(2));
    }

    [Test]
    public async Task DurableProviderRejectsWorkWhileBoundaryIsStartingOrFinished()
    {
        var raw = new IndependentTransactionProvider { BeginGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        var pending = provider.BeginTransactionAsync();

        Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
        raw.BeginGate.SetResult();
        var transaction = await pending;
        await transaction.CommitAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.ThrowsAsync<InvalidOperationException>(() => transaction.CommitAsync());
            Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
        }

        await transaction.DisposeAsync();
        await using var next = await provider.BeginTransactionAsync();
        Assert.That(raw.BeginCount, Is.EqualTo(2));
    }

    [Test]
    public async Task DurableProviderRejectsNestedWorkOutsideActiveRootLifecycle()
    {
        var commitGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var raw = new IndependentTransactionProvider { CompletionGate = commitGate };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        var root = await provider.BeginTransactionAsync();
        var nested = await provider.BeginTransactionAsync();

        Assert.ThrowsAsync<InvalidOperationException>(() => root.CommitAsync());
        Assert.ThrowsAsync<InvalidOperationException>(async () => await root.DisposeAsync());
        await nested.CommitAsync();
        await nested.DisposeAsync();
        var commit = root.CommitAsync();
        Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
        Assert.Throws<ObjectDisposedException>(() => nested.OnCommitted(_ => Task.CompletedTask));
        commitGate.SetResult();
        await commit;
        Assert.ThrowsAsync<ObjectDisposedException>(() => nested.CommitAsync());
        await nested.DisposeAsync();
        await root.DisposeAsync();
        await root.DisposeAsync();

        var unfinishedRoot = await provider.BeginTransactionAsync();
        var unfinishedNested = await provider.BeginTransactionAsync();
        Assert.ThrowsAsync<InvalidOperationException>(async () => await unfinishedRoot.DisposeAsync());
        await unfinishedNested.DisposeAsync();
        await unfinishedRoot.DisposeAsync();
    }

    [Test]
    public async Task DurableProviderRejectsOutOfOrderNestedUsage()
    {
        var provider = AshlarDurableTransactionProvider.Create(new IndependentTransactionProvider());
        await using var root = await provider.BeginTransactionAsync();
        var outer = await provider.BeginTransactionAsync();
        var inner = await provider.BeginTransactionAsync();

        Assert.ThrowsAsync<InvalidOperationException>(() => outer.CommitAsync());
        Assert.ThrowsAsync<InvalidOperationException>(async () => await outer.DisposeAsync());
        Assert.Throws<InvalidOperationException>(() => outer.OnCommitted(_ => Task.CompletedTask));
        Assert.Throws<InvalidOperationException>(() => root.OnCommitted(_ => Task.CompletedTask));

        await inner.CommitAsync();
        await inner.DisposeAsync();
        await outer.CommitAsync();
        Assert.Throws<InvalidOperationException>(() => outer.OnCommitted(_ => Task.CompletedTask));
        await outer.DisposeAsync();
    }

    [Test]
    public async Task DurableProviderDisposesRootOnlyOnceWhenDisposalOverlaps()
    {
        var disposalGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var raw = new IndependentTransactionProvider { DisposalGate = disposalGate };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        var root = await provider.BeginTransactionAsync();

        var first = root.DisposeAsync().AsTask();
        Assert.That(raw.Transaction.DisposeCount, Is.EqualTo(1));
        var second = root.DisposeAsync().AsTask();
        disposalGate.SetResult();

        await Task.WhenAll(first, second);
        Assert.That(raw.Transaction.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public async Task DurableProviderReservesNestedScopeWhileRegisteringHook()
    {
        using var hookStarted = new ManualResetEventSlim();
        using var hookRelease = new ManualResetEventSlim();
        var raw = new IndependentTransactionProvider { HookStarted = hookStarted, HookRelease = hookRelease };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        await using var root = await provider.BeginTransactionAsync();
        var nested = await provider.BeginTransactionAsync();

        var registration = Task.Run(() => nested.OnCommitted(_ => Task.CompletedTask));
        Assert.That(hookStarted.Wait(TimeSpan.FromSeconds(5)), Is.True);
        try
        {
            Assert.ThrowsAsync<InvalidOperationException>(() => root.CommitAsync());
            Assert.ThrowsAsync<InvalidOperationException>(async () => await nested.DisposeAsync());
        }
        finally
        {
            hookRelease.Set();
        }
        await registration;

        await nested.CommitAsync();
        await nested.DisposeAsync();
        await root.CommitAsync();
    }

    [Test]
    public async Task DurableProviderAllowsPostCommitHookToStartANewBoundary()
    {
        var raw = new IndependentTransactionProvider { RunHooksOnCommit = true };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        await using var transaction = await provider.BeginTransactionAsync();
        transaction.OnCommitted(async cancellationToken =>
        {
            await using var next = await provider.BeginTransactionAsync(cancellationToken);
            await next.CommitAsync(cancellationToken);
        });

        await transaction.CommitAsync();

        Assert.That(raw.BeginCount, Is.EqualTo(2));
    }

    [Test]
    public async Task DurableProviderDoesNotReleasePreCommitAmbientContextsForPostCommitHooks()
    {
        var raw = new IndependentTransactionProvider { RunHooksOnCommit = true };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        var hookStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var detachedContextChecked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var transaction = await provider.BeginTransactionAsync();
        var inheritedContext = Task.Run(async () =>
        {
            await hookStarted.Task;
            Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
            detachedContextChecked.SetResult();
        });
        transaction.OnCommitted(async cancellationToken =>
        {
            hookStarted.SetResult();
            await detachedContextChecked.Task.WaitAsync(cancellationToken);
            await using var next = await provider.BeginTransactionAsync(cancellationToken);
            await next.CommitAsync(cancellationToken);
        });

        await transaction.CommitAsync();
        await inheritedContext;

        Assert.That(raw.BeginCount, Is.EqualTo(2));
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task DurableProviderDoesNotRetryAnIndeterminateCompletion(bool commit)
    {
        var raw = new IndependentTransactionProvider { FailCompletion = true };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        var transaction = await provider.BeginTransactionAsync();

        Assert.ThrowsAsync<InvalidOperationException>(() =>
            commit ? transaction.CommitAsync() : transaction.RollbackAsync());
        Assert.ThrowsAsync<InvalidOperationException>(() =>
            commit ? transaction.CommitAsync() : transaction.RollbackAsync());

        await transaction.DisposeAsync();
        await using var next = await provider.BeginTransactionAsync();
        Assert.That(raw.BeginCount, Is.EqualTo(2));
    }

    [Test]
    public async Task DurableProviderDoesNotReopenBoundaryAfterDisposalFails()
    {
        var raw = new IndependentTransactionProvider { FailDisposal = true };
        var provider = AshlarDurableTransactionProvider.Create(raw);
        var transaction = await provider.BeginTransactionAsync();

        Assert.ThrowsAsync<InvalidOperationException>(async () => await transaction.DisposeAsync());
        Assert.ThrowsAsync<InvalidOperationException>(() => provider.BeginTransactionAsync());
    }

    [Test]
    public void ServiceProviderValidationRejectsNullArguments()
    {
        var services = new ServiceCollection();

        using (Assert.EnterMultipleScope())
        {
            Assert.Throws<ArgumentNullException>(() => ServiceProviderValidation.BuildValidatedServiceProvider((IServiceCollection)null!));
            Assert.Throws<ArgumentNullException>(() => ServiceProviderValidation.BuildValidatedServiceProvider(services, null!));
            Assert.Throws<ArgumentNullException>(() => ServiceProviderValidation.BuildValidatedServiceProvider((Action<IServiceCollection>)null!));
        }
    }

    [Test]
    public void ServiceProviderValidationDisposesProviderWhenScopedResolutionFails()
    {
        var disposable = new DisposableDependency();
        var services = new ServiceCollection();
        services.AddSingleton(_ => disposable);

        Assert.Throws<InvalidOperationException>(() =>
            ServiceProviderValidation.BuildValidatedServiceProvider(services, typeof(DisposableDependency), typeof(ScopedDependency)));

        Assert.That(disposable.Disposed, Is.True);
    }

    [Test]
    public void ServiceProviderValidationDisposesProviderWhenValidationScopeDisposalFails()
    {
        var disposable = new DisposableDependency();
        var services = new ServiceCollection();
        services.AddSingleton(_ => disposable);
        services.AddScoped<ThrowingAsyncScopedDependency>();

        Assert.Throws<InvalidOperationException>(() =>
            ServiceProviderValidation.BuildValidatedServiceProvider(services, typeof(DisposableDependency), typeof(ThrowingAsyncScopedDependency)));

        Assert.That(disposable.Disposed, Is.True);
    }

    private sealed class ScopedDependency;

    private interface ICustomOperationalAdministrationService
    {
        AshlarOperationalAdministrationContext Administration { get; }
        ScopedDependency Ordinary { get; }
        int DisposeCount { get; }
    }

    private sealed class CustomOperationalAdministrationService(
        AshlarOperationalAdministrationContext administration,
        ScopedDependency ordinary) : ICustomOperationalAdministrationService, IDisposable
    {
        public AshlarOperationalAdministrationContext Administration { get; } = administration;
        public ScopedDependency Ordinary { get; } = ordinary;
        public int DisposeCount { get; private set; }

        public void Dispose() => DisposeCount++;
    }

    private sealed class DisposableDependency : IAshlarTransactionProvider, IDisposable
    {
        public bool Disposed => DisposeCount != 0;
        public int DisposeCount { get; private set; }

        public void Dispose()
        {
            DisposeCount++;
        }

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class AsyncDisposableDependency : IAshlarTransactionProvider, IAsyncDisposable
    {
        public int DisposeCount { get; private set; }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }

        public Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class ThrowingAsyncScopedDependency : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            return ValueTask.FromException(new InvalidOperationException("Validation scope disposal failed."));
        }
    }

    private sealed class RecordingSecretProtector : ISecretProtector
    {
        public byte[] Protect(byte[] data) => data;

        public byte[] Unprotect(byte[] data) => data;
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class RecordingAuthenticationRateLimiter : IAuthenticationRateLimiter
    {
        public Task<RateLimitDecision> CheckAsync(RateLimitAttempt attempt, RateLimitRule rule, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class IndependentTransactionProvider : IAshlarTransactionProvider
    {
        public int BeginCount { get; private set; }
        public bool FailNextBegin { get; set; }
        public bool ReturnNull { get; set; }
        public TaskCompletionSource? BeginGate { get; set; }
        public TaskCompletionSource? CompletionGate { get; set; }
        public TaskCompletionSource? DisposalGate { get; set; }
        public ManualResetEventSlim? HookStarted { get; set; }
        public ManualResetEventSlim? HookRelease { get; set; }
        public bool RunHooksOnCommit { get; set; }
        public bool FailCompletion { get; set; }
        public bool FailDisposal { get; set; }
        public IndependentTransaction Transaction { get; private set; } = null!;

        public async Task<IAshlarTransaction> BeginTransactionAsync(CancellationToken cancellationToken = default)
        {
            BeginCount++;
            if (FailNextBegin)
            {
                FailNextBegin = false;
                throw new InvalidOperationException("begin failed");
            }
            if (BeginGate is not null) await BeginGate.Task.WaitAsync(cancellationToken);
            if (ReturnNull) return null!;
            Transaction = new IndependentTransaction(CompletionGate, DisposalGate, HookStarted, HookRelease, RunHooksOnCommit, FailCompletion, FailDisposal);
            return Transaction;
        }
    }

    private sealed class IndependentTransaction(
        TaskCompletionSource? completionGate = null,
        TaskCompletionSource? disposalGate = null,
        ManualResetEventSlim? hookStarted = null,
        ManualResetEventSlim? hookRelease = null,
        bool runHooksOnCommit = false,
        bool failCompletion = false,
        bool failDisposal = false) : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];
        public int CommitCount { get; private set; }
        public int RollbackCount { get; private set; }
        public int DisposeCount { get; private set; }
        public int HookCount { get; private set; }
        public async Task CommitAsync(CancellationToken cancellationToken = default)
        {
            CommitCount++;
            if (failCompletion) throw new InvalidOperationException("commit failed");
            if (completionGate is not null) await completionGate.Task.WaitAsync(cancellationToken);
            if (runHooksOnCommit)
                foreach (var hook in _hooks) await hook(CancellationToken.None);
        }
        public Task RollbackAsync(CancellationToken cancellationToken = default)
        {
            RollbackCount++;
            return failCompletion ? Task.FromException(new InvalidOperationException("rollback failed")) : Task.CompletedTask;
        }
        public void OnCommitted(Func<CancellationToken, Task> action)
        {
            hookStarted?.Set();
            hookRelease?.Wait();
            HookCount++;
            _hooks.Add(action);
        }
        public async ValueTask DisposeAsync()
        {
            DisposeCount++;
            if (failDisposal) throw new InvalidOperationException("dispose failed");
            if (disposalGate is not null) await disposalGate.Task;
        }
    }
}
