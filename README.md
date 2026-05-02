# Ashlar
Building blocks for modern ASP.NET applications. Includes generic auth, security, and utility components.

## Identity DI Setup
Ashlar provides `IServiceCollection` extensions for registering its core identity services:

```csharp
services.AddScoped<IIdentityRepository, AppIdentityRepository>();

services.AddDataProtection();
services.AddAshlarDataProtectionSecretProtector();

services.AddAshlarIdentity(options =>
{
    options.LastUsedAtUpdateThreshold = TimeSpan.FromMinutes(5);
});

services
    .AddAuthenticationProvider<LocalPasswordProvider>()
    .AddPasswordHasher<PasswordHasherV1>();
```

Applications must provide an `IIdentityRepository` implementation. Ashlar does not register persistence by default.

Applications must also provide secret protection. For ASP.NET Core Data Protection, register Data Protection and call `AddAshlarDataProtectionSecretProtector()`. Ashlar does not use an insecure fallback protector.

## Contributions
Contributions are welcome! Read the [contributing guide](CONTRIBUTING.md) to get started.

## License
This project is licensed under the [MIT License](LICENSE).
