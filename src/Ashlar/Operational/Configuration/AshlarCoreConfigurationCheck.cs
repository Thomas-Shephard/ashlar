using Ashlar.Authorization;
using Ashlar.Authorization.Abstractions;
using Ashlar.Auditing;
using Ashlar.Identity.Notifications;
using Ashlar.Identity.Providers.Email;
using Ashlar.Identity.Providers.RecoveryCode;
using Ashlar.Identity.RateLimiting;
using Ashlar.Identity.RateLimiting.Abstractions;
using Ashlar.Messaging;
using Ashlar.Security.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Sockets;

namespace Ashlar.Operational.Configuration;

internal sealed class AshlarCoreConfigurationCheck : IAshlarConfigurationCheck
{
    private const string CallbackUriValidationComponent = "Callback URI validation";

    public async ValueTask<IReadOnlyList<AshlarConfigurationIssue>> CheckAsync(
        IServiceProvider serviceProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        cancellationToken.ThrowIfCancellationRequested();

        List<AshlarConfigurationIssue> issues = [];

        AddMissingProviderServiceIssue<IUserRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.UserRepositoryMissing,
            "Identity user persistence is not configured.",
            "Install and configure an Ashlar persistence provider. Provider authors must register IUserRepository through Ashlar.ProviderContracts.",
            "Identity persistence",
            typeof(IIdentityService),
            typeof(ICredentialService),
            typeof(IAccountSecurityService),
            typeof(IUserAdministrationService),
            typeof(IInvitationService),
            typeof(IBootstrapService),
            typeof(IEmailVerificationService),
            typeof(IEmailChangeService),
            typeof(IEmailCodeSignInService),
            typeof(IMagicLinkSignInService),
            typeof(ITotpService),
            typeof(IRecoveryCodeService));

        AddMissingProviderServiceIssue<ICredentialRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.CredentialRepositoryMissing,
            "Credential persistence is not configured.",
            "Install and configure an Ashlar persistence provider. Provider authors must register ICredentialRepository through Ashlar.ProviderContracts.",
            "Credential persistence",
            typeof(ICredentialService),
            typeof(IAccountSecurityService),
            typeof(IUserAdministrationService),
            typeof(IEmailVerificationService),
            typeof(IEmailChangeService),
            typeof(IEmailCodeSignInService),
            typeof(IMagicLinkSignInService),
            typeof(ITotpService),
            typeof(IRecoveryCodeService),
            typeof(RequireMfaWhenCredentialExistsPolicyEvaluator));

        AddMissingServiceIssue<ISecretProtector>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.SecretProtectorMissing,
            "Secret protection is not configured.",
            "Register an ISecretProtector implementation before enabling credential features that store protected values.",
            "Secret protection",
            typeof(ICredentialService),
            typeof(IEmailChangeService));

        AddMissingProviderServiceIssue<IAuthenticationSessionRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing,
            "Authentication session persistence is not configured.",
            "Install and configure an Ashlar persistence provider. Provider authors must register IAuthenticationSessionRepository through Ashlar.ProviderContracts.",
            "Session persistence",
            typeof(IAuthenticationSessionService),
            typeof(IAccountSecurityService),
            typeof(IUserAdministrationService),
            typeof(IEmailChangeService));

        AddMissingServiceIssue<IUserAdministrationRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.UserAdministrationRepositoryMissing,
            "User administration persistence is not configured.",
            "Register an IUserAdministrationRepository implementation, usually from an Ashlar persistence provider.",
            "User administration",
            typeof(IUserAdministrationService));

        AddMissingServiceIssue<ICredentialAdministrationRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.CredentialAdministrationRepositoryMissing,
            "Credential administration persistence is not configured.",
            "Register an ICredentialAdministrationRepository implementation, usually from an Ashlar persistence provider.",
            "Credential administration",
            typeof(ICredentialAdministrationService));

        AddMissingServiceIssue<ISecurityEventAdministrationRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.SecurityEventAdministrationRepositoryMissing,
            "Security event administration persistence is not configured.",
            "Register an ISecurityEventAdministrationRepository implementation, usually from an Ashlar persistence provider.",
            "Security event administration",
            typeof(ISecurityEventAdministrationService));

        AddMissingServiceIssue<IAuthenticationSessionAdministrationRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthenticationSessionAdministrationRepositoryMissing,
            "Authentication session administration persistence is not configured.",
            "Register an IAuthenticationSessionAdministrationRepository implementation, usually from an Ashlar persistence provider.",
            "Session administration",
            typeof(IAuthenticationSessionAdministrationService));

        AddMissingProviderServiceIssue<IInvitationRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.InvitationRepositoryMissing,
            "Invitation persistence is not configured.",
            "Install and configure an Ashlar persistence provider with invitation support.",
            "Invitation persistence",
            typeof(IInvitationService),
            typeof(IInvitationAdministrationService));

        AddMissingProviderServiceIssue<IBootstrapStateRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.BootstrapStateRepositoryMissing,
            "Bootstrap state persistence is not configured.",
            "Install and configure an Ashlar persistence provider with bootstrap support.",
            "Bootstrap persistence",
            typeof(IBootstrapService));

        AddMissingProviderServiceIssue<IAuthenticationHandshakeRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthenticationHandshakeRepositoryMissing,
            "Authentication handshake persistence is not configured.",
            "Install and configure an Ashlar persistence provider with authentication-handshake support.",
            "Authentication handshakes",
            typeof(IAuthenticationHandshakeService));

        AddMissingProviderServiceIssue<IAuthorizationGrantRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthorizationGrantRepositoryMissing,
            "Authorization grant persistence is not configured.",
            "Install and configure an Ashlar persistence provider with authorization-grant support.",
            "Authorization persistence",
            typeof(IAuthorizationGrantService),
            typeof(IAuthorizationEvaluator));

        var scopeFactory = serviceProvider.GetService<IServiceScopeFactory>();
        if (scopeFactory is null)
        {
            AddImplementationIssues(serviceProvider, issues);
            return issues;
        }

        await using var inspectionScope = scopeFactory.CreateAsyncScope();
        AddImplementationIssues(inspectionScope.ServiceProvider, issues);

        return issues;
    }

    private static void AddImplementationIssues(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        AddEmailSenderIssue(serviceProvider, issues);
        AddNullSecurityEventSinkIssue(serviceProvider, issues);
        AddAuthorizationGrantMutationDependencyIssues(serviceProvider, issues);
        AddAccountSecurityOperationAuthorizerIssue(serviceProvider, issues);
        AddPermissiveAccountSecurityGuardIssue(serviceProvider, issues);
        AddMfaPolicyIssues(serviceProvider, issues);
        AddInMemoryRateLimiterIssue(serviceProvider, issues);
        AddInMemorySecurityNotificationSuppressionStoreIssue(serviceProvider, issues);
        AddTransactionProviderIssue(serviceProvider, issues);
        AddBootstrapOptionIssues(serviceProvider, issues);
        AddCallbackUriAllowListIssues(serviceProvider, issues);
    }

    private static void AddMissingServiceIssue<TService>(
        IServiceProvider serviceProvider,
        List<AshlarConfigurationIssue> issues,
        string code,
        string message,
        string recommendation,
        string component,
        params Type[] requiredWhenAnyServiceIsRegistered)
        where TService : class
    {
        if (requiredWhenAnyServiceIsRegistered.Length > 0
            && !requiredWhenAnyServiceIsRegistered.Any(serviceProvider.IsServiceRegistered))
        {
            return;
        }

        if (!serviceProvider.IsServiceRegistered<TService>())
        {
            issues.Add(new AshlarConfigurationIssue(
                code,
                AshlarConfigurationIssueSeverity.Error,
                message,
                recommendation,
                component));
        }
    }

    private static void AddMissingProviderServiceIssue<TService>(
        IServiceProvider serviceProvider,
        List<AshlarConfigurationIssue> issues,
        string code,
        string message,
        string recommendation,
        string component,
        params Type[] requiredWhenAnyServiceIsRegistered)
        where TService : class
    {
        if (requiredWhenAnyServiceIsRegistered.Length > 0
            && !requiredWhenAnyServiceIsRegistered.Any(serviceProvider.IsServiceRegistered))
        {
            return;
        }

        if (!IsProviderServiceRegistered<TService>(serviceProvider))
        {
            issues.Add(new AshlarConfigurationIssue(code, AshlarConfigurationIssueSeverity.Error, message, recommendation, component));
        }
    }

    private static void AddEmailSenderIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (!IsEmailDeliveryRequired(serviceProvider))
        {
            return;
        }

        if (serviceProvider.GetService<IEmailSender>() is null or NullEmailSender)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.EmailSenderNotConfigured,
                AshlarConfigurationIssueSeverity.Warning,
                "Email delivery is not configured, so Ashlar email messages will not be sent.",
                "Register a production IEmailSender or an Ashlar email outbox sender before enabling email-based flows.",
                "Messaging"));
        }
    }

    private static bool IsEmailDeliveryRequired(IServiceProvider serviceProvider)
    {
        return serviceProvider.IsServiceRegistered<IEmailVerificationService>()
            || serviceProvider.IsServiceRegistered<IEmailChangeService>()
            || serviceProvider.IsServiceRegistered<IEmailCodeSignInService>()
            || serviceProvider.IsServiceRegistered<IMagicLinkSignInService>()
            || serviceProvider.IsServiceRegistered<IInvitationService>()
            || serviceProvider.IsServiceRegistered<ISecurityNotificationService>();
    }

    private static bool IsCallbackUriValidationRequired(IServiceProvider serviceProvider)
    {
        return serviceProvider.IsServiceRegistered<IEmailVerificationService>()
            || serviceProvider.IsServiceRegistered<IEmailChangeService>()
            || serviceProvider.IsServiceRegistered<IMagicLinkSignInService>()
            || serviceProvider.IsServiceRegistered<IInvitationService>()
            || serviceProvider.IsServiceRegistered<IPasswordResetService>();
    }

    private static void AddCallbackUriAllowListIssues(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (!IsCallbackUriValidationRequired(serviceProvider))
        {
            return;
        }

        var options = serviceProvider.GetService<IOptions<UriValidationOptions>>()?.Value ?? new UriValidationOptions();
        var hasValidEntry = false;
        var allowedCallbackUris = options.AllowedCallbackUris ?? [];

        foreach (var configuredEntry in allowedCallbackUris)
        {
            var entry = CallbackUriAllowListEntry.Parse(configuredEntry);

            if (entry.Failure == CallbackUriAllowListEntryFailure.Blank)
            {
                AddInvalidCallbackUriAllowListEntryIssue(issues, "blank entry");
                continue;
            }

            if (entry.Failure != CallbackUriAllowListEntryFailure.None)
            {
                AddInvalidCallbackUriAllowListEntryIssue(issues, SummarizeInvalidCallbackUriEntry(entry.Uri));
                continue;
            }

            hasValidEntry = true;
            var uri = entry.Uri!;

            if (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new AshlarConfigurationIssue(
                    AshlarConfigurationIssueCodes.CallbackUriAllowListInsecureScheme,
                    AshlarConfigurationIssueSeverity.Warning,
                    $"Callback URI allow-list entry {SummarizeCallbackUriEntry(uri)} uses HTTP.",
                    "Use HTTPS callback URI allow-list entries for production deployments. Keep HTTP entries only for explicit local development scenarios.",
                    CallbackUriValidationComponent));
            }

            if (IsLocalCallbackAddress(uri))
            {
                issues.Add(new AshlarConfigurationIssue(
                    AshlarConfigurationIssueCodes.CallbackUriAllowListLocalAddress,
                    AshlarConfigurationIssueSeverity.Warning,
                    $"Callback URI allow-list entry {SummarizeCallbackUriEntry(uri)} targets a local, private, link-local, multicast, or unspecified host.",
                    "Use public application hosts for production callback URI allow-list entries. Keep local, private, link-local, multicast, or unspecified entries only for explicit development or internal deployments.",
                    CallbackUriValidationComponent));
            }
        }

        if (!hasValidEntry)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.CallbackUriAllowListMissing,
                AshlarConfigurationIssueSeverity.Error,
                "Callback URI validation is required but no valid callback URI allow-list entries are configured.",
                "Configure UriValidationOptions.AllowedCallbackUris with at least one trusted callback base URI before enabling token-bearing callback flows.",
                CallbackUriValidationComponent));
        }
    }

    private static void AddInvalidCallbackUriAllowListEntryIssue(List<AshlarConfigurationIssue> issues, string summary)
    {
        issues.Add(new AshlarConfigurationIssue(
            AshlarConfigurationIssueCodes.CallbackUriAllowListInvalidEntry,
            AshlarConfigurationIssueSeverity.Error,
            $"Callback URI allow-list contains an invalid entry ({summary}).",
            "Use absolute http or https callback base URIs without credentials, query strings, or fragments.",
            CallbackUriValidationComponent));
    }

    private static string SummarizeCallbackUriEntry(Uri uri)
    {
        var pathSummary = uri.AbsolutePath == "/" ? "root path" : "non-root path";
        return $"scheme '{uri.Scheme}', host '{uri.Host}', {pathSummary}";
    }

    private static string SummarizeInvalidCallbackUriEntry(Uri? uri)
    {
        if (uri is null)
        {
            return "malformed entry";
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return "unsupported scheme";
        }

        return SummarizeCallbackUriEntry(uri);
    }

    private static bool IsLocalCallbackAddress(Uri uri)
    {
        if (uri.IsLoopback)
        {
            return true;
        }

        if (!IPAddress.TryParse(uri.Host, out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (address.IsIPv6Multicast)
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IsPrivateLinkLocalOrMulticastIPv4(address);
        }

        var ipv6Bytes = address.GetAddressBytes();
        return address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal
            || (ipv6Bytes[0] & 0xfe) == 0xfc;
    }

    private static bool IsPrivateLinkLocalOrMulticastIPv4(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] >= 224 && bytes[0] <= 239);
    }

    private static void AddNullSecurityEventSinkIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (serviceProvider.GetAshlarProviderService<IPersistentSecurityEventSink>() is not null
            && serviceProvider.GetService<SecurityEventFanOutSink>() is { RequiresDurableTransaction: true })
        {
            return;
        }

        issues.Add(new AshlarConfigurationIssue(
            AshlarConfigurationIssueCodes.NullSecurityEventSink,
            AshlarConfigurationIssueSeverity.Warning,
            "Security audit events do not have a persistent sink configured, so Ashlar audit events will not be persisted.",
            "Install and configure an Ashlar persistence provider with durable security-event storage.",
            "Security auditing"));
    }

    private static void AddPermissiveAccountSecurityGuardIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (serviceProvider.GetService<IAccountSecurityGuard>() is PermissiveAccountSecurityGuard)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.PermissiveAccountSecurityGuard,
                AshlarConfigurationIssueSeverity.Warning,
                "Account-state changes use PermissiveAccountSecurityGuard, so all guarded account-state changes are allowed.",
                "Keep AddPermissiveAccountSecurityGuard only when this is deliberate. Register an application-specific IAccountSecurityGuard before relying on account-state changes for business approval, risk review, or separation-of-duties controls.",
                "Account security guard"));
        }
    }

    private static void AddAccountSecurityOperationAuthorizerIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if ((serviceProvider.IsServiceRegistered<IAccountSecurityAdministrationService>()
                || serviceProvider.IsServiceRegistered<AuthorizationGrantService>())
            && !serviceProvider.IsServiceRegistered<IAccountSecurityOperationAuthorizer>())
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.AccountSecurityOperationAuthorizerMissing,
                AshlarConfigurationIssueSeverity.Error,
                "Account-security administration requires a host operation authorizer, but none is registered.",
                "Register an application-specific IAccountSecurityOperationAuthorizer that evaluates the actor, target, operation details, and exact tenant, global, or all-tenant scope.",
                "Account security authorization"));
        }
    }

    private static void AddAuthorizationGrantMutationDependencyIssues(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (!serviceProvider.IsServiceRegistered<AuthorizationGrantService>()
            || IsProviderServiceRegistered<IAuthenticationSessionRepository>(serviceProvider)
            || issues.Any(issue => issue.Code == AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing)) return;

        issues.Add(new AshlarConfigurationIssue(
            AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing,
            AshlarConfigurationIssueSeverity.Error,
            "Authentication session persistence is not configured.",
            "Install and configure an Ashlar persistence provider with authentication-session support.",
            "Session persistence"));
    }

    private static void AddMfaPolicyIssues(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (!serviceProvider.IsServiceRegistered<IAuthenticationOrchestrator>())
        {
            return;
        }

        if (!serviceProvider.IsServiceRegistered<IMfaPolicyEvaluator>())
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.MfaPolicyMissing,
                AshlarConfigurationIssueSeverity.Error,
                "MFA orchestration is registered without an MFA policy evaluator.",
                "Register AddAshlarNoMfaPolicy, AddAshlarRequireMfaForAllUsers, AddAshlarRequireMfaWhenCredentialExists, or a custom IMfaPolicyEvaluator before resolving IAuthenticationOrchestrator.",
                "MFA policy"));
        }

        if (TryResolveMfaPolicyEvaluator(serviceProvider) is NoMfaPolicyEvaluator)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.PermissiveMfaPolicy,
                AshlarConfigurationIssueSeverity.Warning,
                "MFA orchestration uses NoMfaPolicyEvaluator, so registered MFA factors are available but not required by policy before session issuance.",
                "Keep AddAshlarNoMfaPolicy only for applications that deliberately allow primary authentication to complete without policy-required MFA. Register AddAshlarRequireMfaForAllUsers, AddAshlarRequireMfaWhenCredentialExists, or a custom IMfaPolicyEvaluator to enforce MFA.",
                "MFA policy"));
        }
    }

    private static IMfaPolicyEvaluator? TryResolveMfaPolicyEvaluator(IServiceProvider serviceProvider)
    {
        try
        {
            return serviceProvider.GetService<IMfaPolicyEvaluator>();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (OptionsValidationException)
        {
            return null;
        }
    }

    private static void AddInMemoryRateLimiterIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (serviceProvider.GetService<IAuthenticationRateLimiter>() is InMemoryAuthenticationRateLimiter)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.InMemoryAuthenticationRateLimiter,
                AshlarConfigurationIssueSeverity.Warning,
                "Authentication rate limiting uses the in-memory implementation, which is process-local, resets on process restart, and does not coordinate across multiple app instances.",
                "Use PostgreSQL, SQLite, or Redis-backed rate limiting depending on deployment shape. Use Redis or PostgreSQL for multi-instance deployments; SQLite is persistent but still single-instance oriented.",
                "Authentication rate limiting"));
        }
    }

    private static void AddInMemorySecurityNotificationSuppressionStoreIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (!serviceProvider.IsServiceRegistered<ISecurityNotificationService>())
        {
            return;
        }

        if (serviceProvider.GetService<ISecurityNotificationSuppressionStore>() is InMemorySecurityNotificationSuppressionStore)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.InMemorySecurityNotificationSuppressionStore,
                AshlarConfigurationIssueSeverity.Warning,
                "Security notification suppression uses the in-memory implementation.",
                "This is fine for local development, but distributed production deployments should use a shared suppression store.",
                "Security notifications"));
        }
    }

    private static void AddTransactionProviderIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        var transactionProvider = serviceProvider.GetService<AshlarDurableTransactionProvider>();
        if (transactionProvider is not null)
        {
            return;
        }

        var hasDurableRepositories =
            IsProviderServiceRegistered<IUserRepository>(serviceProvider)
            || IsProviderServiceRegistered<ICredentialRepository>(serviceProvider)
            || IsProviderServiceRegistered<IAuthenticationSessionRepository>(serviceProvider)
            || IsProviderServiceRegistered<IAuthenticationHandshakeRepository>(serviceProvider)
            || IsProviderServiceRegistered<IInvitationRepository>(serviceProvider)
            || IsProviderServiceRegistered<IBootstrapStateRepository>(serviceProvider)
            || IsProviderServiceRegistered<IAuthorizationGrantRepository>(serviceProvider)
            || IsProviderServiceRegistered<IAccountLockoutRepository>(serviceProvider)
            || IsProviderServiceRegistered<IRememberedMfaDeviceRepository>(serviceProvider)
            || IsProviderServiceRegistered<IPasskeyChallengeRepository>(serviceProvider)
            || IsProviderServiceRegistered<IAuthenticationRateLimitAdministrationRepository>(serviceProvider)
            || IsProviderServiceRegistered<IPersistentSecurityEventSink>(serviceProvider);

        issues.Add(new AshlarConfigurationIssue(
            AshlarConfigurationIssueCodes.TransactionProviderMissing,
            hasDurableRepositories ? AshlarConfigurationIssueSeverity.Warning : AshlarConfigurationIssueSeverity.Information,
            "No Ashlar transaction provider is configured.",
            hasDurableRepositories
                ? "Install and configure an Ashlar persistence provider. Provider authors must compose its durable transaction through Ashlar.ProviderContracts."
                : "Install and configure an Ashlar persistence provider before using persistent data.",
            "Transactions"));
    }

    private static bool IsProviderServiceRegistered<TService>(IServiceProvider serviceProvider)
        where TService : class =>
        serviceProvider.GetService<IServiceProviderIsService>()?.IsService(typeof(AshlarProviderService<TService>)) == true;

    private static void AddBootstrapOptionIssues(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        if (!serviceProvider.IsServiceRegistered<IBootstrapService>())
        {
            return;
        }

        var options = GetBootstrapOptions(serviceProvider, issues);
        if (options is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(options.SetupSecret))
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.BootstrapSetupAuthorizationMissing,
                AshlarConfigurationIssueSeverity.Error,
                "Bootstrap setup authorization is required but no setup secret is configured.",
                "Configure BootstrapOptions.SetupSecret with an operator-controlled setup secret.",
                "Bootstrap authorization"));
        }

        if (options.Grants.Count > 0 && !serviceProvider.IsServiceRegistered<IAuthorizationGrantBootstrapService>())
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.BootstrapGrantServiceMissing,
                AshlarConfigurationIssueSeverity.Error,
                "Bootstrap grants are configured but authorization services are not registered.",
                "Register Ashlar authorization services before assigning grants during bootstrap, or remove BootstrapOptions.Grants.",
                "Bootstrap authorization"));
        }
    }

    private static BootstrapOptions? GetBootstrapOptions(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        try
        {
            return serviceProvider.GetService<IOptions<BootstrapOptions>>()?.Value ?? new BootstrapOptions();
        }
        catch (OptionsValidationException)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.BootstrapOptionsInvalid,
                AshlarConfigurationIssueSeverity.Error,
                "Bootstrap options are invalid.",
                "Fix BootstrapOptions so each grant has exactly one role or permission and complete scope settings.",
                "Bootstrap authorization"));
            return null;
        }
    }
}

internal static class AshlarConfigurationServiceProviderExtensions
{
    internal static bool IsServiceRegistered<TService>(this IServiceProvider serviceProvider)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        return serviceProvider.IsServiceRegistered(typeof(TService));
    }

    internal static bool IsServiceRegistered(this IServiceProvider serviceProvider, Type serviceType)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(serviceType);

        try
        {
            var isService = serviceProvider as IServiceProviderIsService
                ?? serviceProvider.GetService<IServiceProviderIsService>();
            if (isService is not null)
            {
                return isService.IsService(serviceType);
            }

            return serviceProvider.GetService(serviceType) != null;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }
}
