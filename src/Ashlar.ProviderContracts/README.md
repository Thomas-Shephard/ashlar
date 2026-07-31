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

For now, provider authors should add their test assembly to `InternalsVisibleTo` in the in-repo `tests/Ashlar.ProviderContractTests` project, reference that project, inherit the relevant contract bases, and run their provider test project. Test-only aliases belong there; distributing those contract tests separately remains an open issue.
