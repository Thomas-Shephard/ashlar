# Ashlar.AspNetCore

ASP.NET Core integration for Ashlar session authentication and authorization policies.

## Installation

```bash
dotnet add package Ashlar.AspNetCore
```

## Minimal Usage

Register Ashlar core services, persistence, and ASP.NET Core session cookies:

```csharp
services.AddAshlarIdentity();
services.AddAshlarPostgres(connectionString);

services.AddAshlarAspNetCoreSessions(options =>
{
    options.CookieName = "__Host-ashlar";
});
```

Use the middleware in the normal ASP.NET Core order:

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

Sign users in by creating an Ashlar authentication session and issuing the configured cookie:

```csharp
var signInManager = httpContext.RequestServices.GetRequiredService<IAshlarSignInManager>();
await signInManager.SignInAsync(httpContext, userId);
```

Authorization policies can be backed by Ashlar authorization grants:

```csharp
services.AddAshlarAuthorization();
services.AddAshlarAspNetCoreAuthorization(options =>
{
    options.AddRolePolicy("admin", "admin");
    options.AddPermissionPolicy("project.manage", "project.manage", scope =>
    {
        scope.ScopeType = "project";
        scope.ScopeIdRouteValueName = "projectId";
    });
});
```

## Related Packages

- `Ashlar`: Core identity, authorization, messaging, and security primitives.
- `Ashlar.Postgres`: PostgreSQL persistence for sessions, users, credentials, invitations, and authorization grants.
- `Ashlar.Email.Smtp`: SMTP email delivery for Ashlar email flows.
