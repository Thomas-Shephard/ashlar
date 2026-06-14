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

        AddMissingServiceIssue<IUserRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.UserRepositoryMissing,
            "Identity user persistence is not configured.",
            "Register a durable IUserRepository implementation, usually from an Ashlar persistence provider.",
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

        AddMissingServiceIssue<ICredentialRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.CredentialRepositoryMissing,
            "Credential persistence is not configured.",
            "Register a durable ICredentialRepository implementation, usually from an Ashlar persistence provider.",
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

        AddMissingServiceIssue<IAuthenticationSessionRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthenticationSessionRepositoryMissing,
            "Authentication session persistence is not configured.",
            "Register an IAuthenticationSessionRepository implementation, usually from an Ashlar persistence provider.",
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

        AddMissingServiceIssue<IInvitationRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.InvitationRepositoryMissing,
            "Invitation persistence is not configured.",
            "Register an IInvitationRepository implementation before using Ashlar invitations.",
            "Invitation persistence",
            typeof(IInvitationService),
            typeof(IInvitationAdministrationService));

        AddMissingServiceIssue<IBootstrapStateRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.BootstrapStateRepositoryMissing,
            "Bootstrap state persistence is not configured.",
            "Register an IBootstrapStateRepository implementation before using Ashlar bootstrap flows.",
            "Bootstrap persistence",
            typeof(IBootstrapService));

        AddMissingServiceIssue<IAuthenticationHandshakeRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthenticationHandshakeRepositoryMissing,
            "Authentication handshake persistence is not configured.",
            "Register an IAuthenticationHandshakeRepository implementation before using Ashlar MFA handshakes or orchestration.",
            "Authentication handshakes",
            typeof(IAuthenticationHandshakeService));

        AddMissingServiceIssue<IAuthorizationGrantRepository>(
            serviceProvider,
            issues,
            AshlarConfigurationIssueCodes.AuthorizationGrantRepositoryMissing,
            "Authorization grant persistence is not configured.",
            "Register an IAuthorizationGrantRepository implementation before using Ashlar authorization grants, including bootstrap grant assignment.",
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
        AddInMemoryRateLimiterIssue(serviceProvider, issues);
        AddInMemorySecurityNotificationSuppressionStoreIssue(serviceProvider, issues);
        AddNullTransactionProviderIssue(serviceProvider, issues);
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
        if (serviceProvider.GetService<IPersistentSecurityEventSink>() is null)
        {
            issues.Add(new AshlarConfigurationIssue(
                AshlarConfigurationIssueCodes.NullSecurityEventSink,
                AshlarConfigurationIssueSeverity.Warning,
                "Security audit events do not have a persistent sink configured, so Ashlar audit events will not be persisted.",
                "Register a production IPersistentSecurityEventSink, usually from an Ashlar persistence provider.",
                "Security auditing"));
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

    private static void AddNullTransactionProviderIssue(IServiceProvider serviceProvider, List<AshlarConfigurationIssue> issues)
    {
        var transactionProvider = serviceProvider.GetService<IAshlarTransactionProvider>();
        if (transactionProvider is not null and not NullTransactionProvider)
        {
            return;
        }

        var hasDurableRepositories =
            serviceProvider.IsServiceRegistered<IUserRepository>()
            || serviceProvider.IsServiceRegistered<ICredentialRepository>()
            || serviceProvider.IsServiceRegistered<IUserAdministrationRepository>()
            || serviceProvider.IsServiceRegistered<ICredentialAdministrationRepository>()
            || serviceProvider.IsServiceRegistered<ISecurityEventAdministrationRepository>()
            || serviceProvider.IsServiceRegistered<IAuthenticationSessionRepository>()
            || serviceProvider.IsServiceRegistered<IAuthenticationSessionAdministrationRepository>()
            || serviceProvider.IsServiceRegistered<IAuthenticationHandshakeRepository>()
            || serviceProvider.IsServiceRegistered<IInvitationRepository>()
            || serviceProvider.IsServiceRegistered<IBootstrapStateRepository>()
            || serviceProvider.IsServiceRegistered<IAuthorizationGrantRepository>();

        issues.Add(new AshlarConfigurationIssue(
            AshlarConfigurationIssueCodes.NullTransactionProvider,
            hasDurableRepositories ? AshlarConfigurationIssueSeverity.Warning : AshlarConfigurationIssueSeverity.Information,
            "Ashlar transactions use the null transaction provider.",
            hasDurableRepositories
                ? "Register a durable IAshlarTransactionProvider that coordinates the configured repositories."
                : "No durable repository setup was detected. Review this before using Ashlar with persistent data.",
            "Transactions"));
    }

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

        if (options.Grants.Count > 0 && !serviceProvider.IsServiceRegistered<IAuthorizationGrantService>())
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

/// <summary>
/// Provides safe service registration inspection helpers for Ashlar configuration diagnostics.
/// </summary>
public static class AshlarConfigurationServiceProviderExtensions
{
    /// <summary>
    /// Determines whether the specified service type is registered.
    /// </summary>
    /// <typeparam name="TService">The service type to inspect.</typeparam>
    /// <param name="serviceProvider">The service provider to inspect.</param>
    /// <returns><see langword="true" /> when the service appears to be registered; otherwise <see langword="false" />.</returns>
    public static bool IsServiceRegistered<TService>(this IServiceProvider serviceProvider)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        return serviceProvider.IsServiceRegistered(typeof(TService));
    }

    /// <summary>
    /// Determines whether the specified service type is registered.
    /// </summary>
    /// <param name="serviceProvider">The service provider to inspect.</param>
    /// <param name="serviceType">The service type to inspect.</param>
    /// <returns><see langword="true" /> when the service appears to be registered; otherwise <see langword="false" />.</returns>
    public static bool IsServiceRegistered(this IServiceProvider serviceProvider, Type serviceType)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(serviceType);

        try
        {
            var isService = serviceProvider.GetService<IServiceProviderIsService>();
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
