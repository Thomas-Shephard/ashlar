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
    public void CoreIdentityCompositionBuildsWithStrictValidationAndRequiredTestDoubles()
    {
        var secretProtector = new RecordingSecretProtector();
        var emailSender = new RecordingEmailSender();
        var rateLimiter = new RecordingAuthenticationRateLimiter();
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IUserRepository>());
        services.AddSingleton(Mock.Of<ICredentialRepository>());
        services.AddSingleton(Mock.Of<IUserAdministrationRepository>());
        services.AddSingleton(Mock.Of<ICredentialAdministrationRepository>());
        services.AddSingleton(Mock.Of<IAuthenticationSessionRepository>());
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
            typeof(IAshlarTransactionProvider),
            typeof(IAuthenticationRateLimiterDiagnostics),
            typeof(IAshlarOperationsSummaryService));
        using var scope = provider.CreateScope();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(scope.ServiceProvider.GetRequiredService<ISecretProtector>(), Is.SameAs(secretProtector));
            Assert.That(scope.ServiceProvider.GetRequiredService<IEmailSender>(), Is.SameAs(emailSender));
            Assert.That(scope.ServiceProvider.GetRequiredService<IAuthenticationRateLimiter>(), Is.SameAs(rateLimiter));
            Assert.That(scope.ServiceProvider.GetRequiredService<IAshlarTransactionProvider>(), Is.TypeOf<RecordingTransactionProvider>());
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
        public bool Disposed { get; private set; }

        public void Dispose()
        {
            Disposed = true;
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
}
