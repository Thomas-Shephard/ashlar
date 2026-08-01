# Ashlar.ProviderContracts

Provider-authoring APIs for Ashlar persistence packages.

Applications should install an Ashlar persistence provider such as `Ashlar.Postgres` or `Ashlar.Sqlite` and should not reference this package directly. Custom persistence providers reference this package explicitly to register mutation repositories in Ashlar's provider-owned DI lane and declare the participants sharing their durable transaction boundary. The complete repository set enlisted by `AddAshlarIdentityDurableTransactionParticipants()` is:

- `IUserRepository`
- `ICredentialRepository`
- `IAccountLockoutRepository`
- `IInvitationRepository`
- `IAuthenticationSessionRepository`
- `IRememberedMfaDeviceRepository`
- `IPasskeyChallengeRepository`
- `IAuthorizationGrantRepository`

Register each contract with `TryAddAshlarProviderScoped` (as illustrated for `IUserRepository` below) before declaring the bundle's participants:

```csharp
using Ashlar.ProviderContracts.DependencyInjection;

services.AddAshlarDurableTransactionProvider<CustomTransactionProvider>("Custom");
services.TryAddAshlarProviderScoped<CustomTransactionProvider, IUserRepository, CustomUserRepository>("Custom");
services.AddAshlarIdentityDurableTransactionParticipants();
```

These repository and transaction registrations are provider-owned infrastructure, not app-facing services. Applications install the completed persistence provider and use Ashlar's application-facing identity services; they do not register or replace the provider-owned repositories through ordinary DI.

Operational administration implementations use constructor injection for ordinary application services and an `AshlarOperationalAdministrationContext` containing only the precomposed authorization and audit boundaries:

```csharp
services.ReplaceAshlarOperationalAdministrationScoped<CustomTransactionProvider,
    IEmailOutboxAdministrationService, CustomEmailOutboxAdministrationService>(
    "Custom", AshlarOperationalAdministrationKind.EmailOutbox);
```

## Provider contract tests

Add `Ashlar.ProviderContractTests` to the provider's NUnit test project, then inherit each applicable contract suite. The provider test project owns its database lifecycle and any aliases that expose provider implementations only to the tests:

```csharp
using Ashlar.ProviderContractTests.Identity;
using Ashlar.Identity.Abstractions.Repositories;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

[TestFixture]
public sealed class CustomUserRepositoryContractTests : UserRepositoryContractTests
{
    private string? _databasePath;

    protected override async Task<IServiceProvider> CreateInitializedServiceProviderAsync()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"custom-{Guid.NewGuid():N}.db");
        var services = new ServiceCollection();
        services.AddCustomAshlarProvider(_databasePath);
        services.AddScoped<IUserRepository, CustomUserRepository>(); // test-only alias
        var provider = services.BuildServiceProvider();
        await provider.InitializeCustomProviderAsync();
        return provider;
    }

    protected override Task CleanupInitializedServiceProviderAsync()
    {
        if (_databasePath is not null) File.Delete(_databasePath);
        return Task.CompletedTask;
    }
}
```

Run the inherited tests normally with `dotnet test`. Opt into only the suites the provider supports; for example, a rate-limiting-only provider can inherit the rate-limiter contracts without implementing relational repository or outbox fixtures.
