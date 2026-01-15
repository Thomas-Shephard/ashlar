# GitHub Copilot Instructions for Ashlar

This file provides deep context and strict guidelines for working on the Ashlar repository. Adhere to these instructions for all code generation and review tasks.

## 1. High Level Details

**Summary:**
Ashlar is a flexible, secure Identity and Authentication library for .NET. It provides abstractions for identity management, supporting local password authentication and external providers via a strategy pattern. It handles credential storage, encryption, and hashing with a strong focus on security best practices.

**Tech Stack:**
*   **Frameworks:** .NET 8.0, .NET 9.0, .NET 10.0
*   **Project Type:** .NET Class Library (NuGet Package)
*   **Test Framework:** NUnit
*   **Mocking:** Moq
*   **Key Libraries:** `Microsoft.AspNetCore.DataProtection.Abstractions`

## 2. Build and Validate

Use the following **exact** CLI commands to build, test, and validate the project. Do not guess or use standard defaults if they differ from these.

*   **Restore Tools:**
    ```bash
    dotnet tool restore
    ```

*   **Build (Release):**
    ```bash
    dotnet build Ashlar.slnx --configuration Release
    ```

*   **Test (with Coverage):**
    ```bash
    dotnet test Ashlar.slnx --configuration Release --no-build --settings .runsettings --results-directory ./coverage
    ```

*   **Linting & Quality:**
    *   The project enforces `AnalysisLevel` as `latest-recommended` and `TreatWarningsAsErrors` as `true`.
    *   **Strict Coverage:** 100% line and branch coverage is enforced.
    *   **Coverage Check Command:**
        ```bash
        dotnet coveragechecker --format Cobertura --glob-patterns 'coverage/**/coverage.cobertura.xml' --line-threshold 100 --branch-threshold 100
        ```

## 3. Project Layout

*   `src/Ashlar/` - Core library source code.
    *   `Identity/` - Main identity services (`IdentityService`).
    *   `Identity/Abstractions/` - Core interfaces (`IIdentityService`, `IUser`, `ITenantUser`, `IIdentityRepository`, `IAuthenticationProvider`).
    *   `Identity/Models/` - Data models (`Tenant`, `UserCredential`).
    *   `Identity/Providers/` - Authentication strategies (`LocalPasswordProvider`, `ExternalAuthenticationProvider`).
    *   `Security/` - Encryption (`ISecretProtector`) and Hashing (`IPasswordHasher`) utilities.
*   `tests/Ashlar.Tests/` - Unit tests mirroring the source structure.
*   `artifacts/` - Build outputs.
*   `.github/workflows/` - CI/CD definitions.

## 4. Coding & Architectural Standards (Strict)

*   **Polymorphism:** Prefer polymorphic behavior via interfaces (e.g., `IAuthenticationProvider`) over `if/else` or `switch` statements on types or enums.
*   **Immutability:** Use `readonly` properties, `IReadOnlyDictionary`, and `record` types for data structures that do not require mutation.
*   **Logging:** Use the `[LoggerMessage]` attribute and source generators for high-performance logging. Avoid direct calls to `LogInformation` or `LogError`.
*   **Namespaces:** strictly use **File-scoped namespaces** (e.g., `namespace Ashlar.Identity;`).
*   **Async/Await:** Always use `await` for asynchronous operations. Never use `.Result` or `.Wait()`.
*   **Argument Validation:** Use `ArgumentNullException.ThrowIfNull(...)` or `ArgumentException.ThrowIfNullOrWhiteSpace(...)` at the beginning of methods.

## 5. Security Guidelines

This project deals with sensitive identity data. Security is paramount.

*   **Timing Attacks:** Be hyper-aware of timing attacks when comparing hashes or secrets. Use constant-time comparison methods where appropriate.
*   **Response Discrepancy Oracles:** Ensure that authentication failures (e.g., "User not found" vs "Wrong password") return generic error responses to prevent user enumeration, while still allowing internal diagnostics where safe.
*   **Secrets Management:** Never hardcode secrets. Ensure `ISecretProtector` is used for sensitive data at rest.
*   **Hashing:** Ensure password hashing uses strong algorithms (e.g., PBKDF2/Argon2) via the `IPasswordHasher` abstraction.

## 6. Review Checklist
When reviewing code or suggesting changes, you **MUST** check for the following:

1.  **Documentation Updates (CRITICAL):**
    *   If changes were made to CLI arguments, public APIs, configuration logic, or core architecture:
    *   **Action:** Verify that ALL relevant documentation is updated. This includes `README.md`, `CONTRIBUTING.md`, XML documentation comments (`/// <summary>`), and these `copilot-instructions.md` themselves. If any documentation is missing or outdated, **explicitly flag this** in your review.
2.  **Violations of Polymorphism:** Flag usages of `GetType()` or unnecessary `switch` statements on types.
3.  **Security Leaks:**
    *   Identify logic that might introduce side-channel vulnerabilities (timing/error discrepancies) or XXE vectors.
    *   Ensure all inputs are validated and secrets are protected using `ISecretProtector`.
4.  **Missing Tests & Coverage:**
    *   Every new feature or bug fix **must** include NUnit tests. Mock external dependencies using Moq.
    *   **Strict Coverage:** Verify that 100% line and branch coverage is maintained.
5.  **Strict Typing:** Flag usages of `dynamic` or unnecessary `object` types where a strong type or generic could be used.
6.  **Conventions:** Ensure file-scoped namespaces are used and the coding style remains consistent with the project.
