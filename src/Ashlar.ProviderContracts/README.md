# Ashlar.ProviderContracts

Provider-authoring APIs for Ashlar persistence packages.

Applications should install an Ashlar persistence provider such as `Ashlar.Postgres` or `Ashlar.Sqlite` and should not reference this package directly. Custom persistence providers reference this package explicitly to register mutation repositories in Ashlar's provider-owned DI lane and declare the participants sharing their durable transaction boundary.

```csharp
using Ashlar.ProviderContracts.DependencyInjection;

services.AddAshlarDurableTransactionProvider<CustomTransactionProvider>("Custom");
services.TryAddAshlarProviderScoped<CustomTransactionProvider, IUserRepository, CustomUserRepository>("Custom");
services.AddAshlarIdentityDurableTransactionParticipants();
```

Operational administration implementations use constructor injection for ordinary application services and an `AshlarOperationalAdministrationContext` containing only the precomposed authorization and audit boundaries:

```csharp
services.ReplaceAshlarOperationalAdministrationScoped<CustomTransactionProvider,
    IEmailOutboxAdministrationService, CustomEmailOutboxAdministrationService>(
    "Custom", AshlarOperationalAdministrationKind.EmailOutbox);
```

Provider contract tests register test-only aliases in their provider test projects. Ordinary application DI does not expose provider-owned services.
