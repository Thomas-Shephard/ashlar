# Ashlar.ProviderContracts

Provider-authoring APIs for Ashlar persistence packages.

Applications should install an Ashlar persistence provider such as `Ashlar.Postgres` or `Ashlar.Sqlite` and should not reference this package directly. Custom persistence providers reference this package explicitly to register mutation repositories in Ashlar's provider-owned DI lane and declare the participants sharing their durable transaction boundary.

```csharp
using Ashlar.ProviderContracts.DependencyInjection;

services.TryAddAshlarProviderScoped<IUserRepository, CustomUserRepository>();
services.AddAshlarDurableTransactionProvider<CustomTransactionProvider>();
services.AddAshlarIdentityDurableTransactionParticipants();
```

Provider contract tests can resolve provider-owned services with `GetRequiredAshlarProviderService<TService>()`. Ordinary application DI does not expose those services.
