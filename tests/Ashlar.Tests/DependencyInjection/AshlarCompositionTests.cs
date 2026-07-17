using Ashlar.Auditing;
using Ashlar.Identity.Providers.Local;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Identity.RateLimiting.Models;
using Ashlar.Messaging;
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
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>();
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
        services.AddAshlarDurableTransactionProvider<RecordingTransactionProvider>();
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

        Assert.That(AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<ScopedDependency>(providerServiceProvider), Is.Not.Null);
        Assert.Throws<InvalidOperationException>(() =>
            AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<ScopedDependency>(ordinaryProvider));
    }

    [Test]
    public void ProviderRegistrationRejectsNullServiceInstances()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped<ScopedDependency>(_ => null!);
        using var provider = services.BuildServiceProvider();

        Assert.Throws<ArgumentNullException>(() =>
            AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<ScopedDependency>(provider));
    }

    [Test]
    public void ProviderServicesDoNotExposeRawContractsThroughServiceDescriptors()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => Mock.Of<IUserRepository>());

        using var provider = services.BuildServiceProvider();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(services.Any(descriptor => descriptor.ServiceType == typeof(IUserRepository)), Is.False);
            Assert.That(provider.GetService<IUserRepository>(), Is.Null);
            Assert.That(services.Where(descriptor => descriptor.ServiceKey is not null)
                .Select(descriptor => provider.GetKeyedService(typeof(IUserRepository), descriptor.ServiceKey!)), Is.All.Null);
            Assert.That(AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<IUserRepository>(provider), Is.Not.Null);
        }
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
            _ = AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<DisposableDependency>(scope.ServiceProvider);
            _ = AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<AsyncDisposableDependency>(scope.ServiceProvider);
            _ = AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<ScopedDependency>(scope.ServiceProvider);
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
            _ = AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<DisposableDependency>(scope.ServiceProvider);

        Assert.That(dependency.DisposeCount, Is.EqualTo(1));
    }

    [Test]
    public void ProviderWrapperRejectsSynchronousDisposalOfAsyncOnlyResource()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => new AsyncDisposableDependency());
        using var provider = services.BuildServiceProvider();
        var scope = provider.CreateScope();
        _ = AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<AsyncDisposableDependency>(scope.ServiceProvider);

        Assert.Throws<InvalidOperationException>(scope.Dispose);
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
            Assert.That(AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<IUserRepository>(provider), Is.SameAs(providerRepository));
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
    public void FreshProofValidationIsProviderOwned()
    {
        var services = new ServiceCollection();
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddAshlarIdentity();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetService<IFreshAuthenticationProofValidator>(), Is.Null);
            Assert.That(AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<IFreshAuthenticationProofValidator>(scope.ServiceProvider), Is.Not.Null);
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
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddAshlarProviderScoped(_ => Mock.Of<IAuthenticationSessionRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionAdministrationRepository>());
        services.AddSingleton(Mock.Of<ISecurityEventAdministrationRepository>());
        services.AddSingleton<ISecretProtector>(secretProtector);
        services.AddSingleton<IEmailSender>(emailSender);
        services.AddSingleton<IAuthenticationRateLimiter>(rateLimiter);
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
            Assert.That(scope.ServiceProvider.GetRequiredService<AshlarDurableTransactionProvider>(), Is.TypeOf<AshlarDurableTransactionProvider>());
            Assert.That(AshlarProviderServiceCollectionExtensions.GetRequiredAshlarProviderService<RecordingTransactionProvider>(scope.ServiceProvider), Is.Not.Null);
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
                Assert.ThrowsAsync<InvalidOperationException>(() => rollbackOuter.CommitAsync());
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

        var commit = root.CommitAsync();
        Assert.Throws<InvalidOperationException>(() => nested.OnCommitted(_ => Task.CompletedTask));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await root.DisposeAsync());
        commitGate.SetResult();
        await commit;
        Assert.ThrowsAsync<InvalidOperationException>(() => nested.CommitAsync());
        await nested.DisposeAsync();
        await nested.DisposeAsync();
        await root.DisposeAsync();
        await root.DisposeAsync();

        var unfinishedRoot = await provider.BeginTransactionAsync();
        var unfinishedNested = await provider.BeginTransactionAsync();
        await unfinishedRoot.DisposeAsync();
        Assert.ThrowsAsync<InvalidOperationException>(() => unfinishedNested.CommitAsync());
        await unfinishedNested.DisposeAsync();
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

    private sealed class DisposableDependency : IDisposable
    {
        public bool Disposed => DisposeCount != 0;
        public int DisposeCount { get; private set; }

        public void Dispose()
        {
            DisposeCount++;
        }
    }

    private sealed class AsyncDisposableDependency : IAsyncDisposable
    {
        public int DisposeCount { get; private set; }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
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
            Transaction = new IndependentTransaction(CompletionGate, RunHooksOnCommit, FailCompletion, FailDisposal);
            return Transaction;
        }
    }

    private sealed class IndependentTransaction(TaskCompletionSource? completionGate = null, bool runHooksOnCommit = false, bool failCompletion = false, bool failDisposal = false) : IAshlarTransaction
    {
        private readonly List<Func<CancellationToken, Task>> _hooks = [];
        public int CommitCount { get; private set; }
        public int RollbackCount { get; private set; }
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
        public void OnCommitted(Func<CancellationToken, Task> action) { HookCount++; _hooks.Add(action); }
        public ValueTask DisposeAsync() => failDisposal
            ? ValueTask.FromException(new InvalidOperationException("dispose failed"))
            : ValueTask.CompletedTask;
    }
}
