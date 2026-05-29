using System.Globalization;
using System.Collections.ObjectModel;
using Ashlar.Auditing;
using Ashlar.Identity.Models.Totp;
using Ashlar.Identity.Providers.RecoveryCode;
using Microsoft.Extensions.Options;

namespace Ashlar.Identity.Features.AccountSecurity;

/// <summary>
/// Implements administrator-oriented account security operations.
/// </summary>
/// <param name="userRepository">Stores and retrieves users.</param>
/// <param name="credentialRepository">Stores and retrieves credentials.</param>
/// <param name="sessionService">The session service value.</param>
/// <param name="transactionProvider">The transaction provider value.</param>
/// <param name="accountSecurityGuard">The account security guard value.</param>
/// <param name="dependencies">The dependencies value.</param>
public sealed class AccountSecurityService : IAccountSecurityService
{
    private const string AdminReason = "admin";
    private readonly IUserRepository _userRepository;
    private readonly ICredentialRepository _credentialRepository;
    private readonly IAuthenticationSessionService _sessionService;
    private readonly IAshlarTransactionProvider _transactionProvider;
    private readonly IAccountSecurityGuard _accountSecurityGuard;
    private readonly TimeProvider _timeProvider;
    private readonly SecurityEventEmitter _securityEvents;
    private readonly IUserSecurityEventSummaryRepository? _securityEventSummaryRepository;
    private readonly IMfaPolicyEvaluator _mfaPolicyEvaluator;
    private readonly IAuthenticationProviderRegistry? _providerRegistry;
    private readonly AuthenticationProviderKey _totpProvider;
    private readonly AuthenticationProviderKey _recoveryCodeProvider;

    /// <summary>
    /// Initializes a configured service instance.
    /// </summary>
    /// <param name="userRepository">Stores and retrieves users.</param>
    /// <param name="credentialRepository">Stores and retrieves credentials.</param>
    /// <param name="sessionService">The session service value.</param>
    /// <param name="transactionProvider">The transaction provider value.</param>
    /// <param name="accountSecurityGuard">The account security guard value.</param>
    /// <param name="dependencies">The dependencies value.</param>
    public AccountSecurityService(
        IUserRepository userRepository,
        ICredentialRepository credentialRepository,
        IAuthenticationSessionService sessionService,
        IAshlarTransactionProvider transactionProvider,
        IAccountSecurityGuard accountSecurityGuard,
        AccountSecurityServiceDependencies dependencies)
    {
        ArgumentNullException.ThrowIfNull(dependencies);

        _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        _credentialRepository = credentialRepository ?? throw new ArgumentNullException(nameof(credentialRepository));
        _sessionService = sessionService ?? throw new ArgumentNullException(nameof(sessionService));
        _transactionProvider = transactionProvider ?? throw new ArgumentNullException(nameof(transactionProvider));
        _accountSecurityGuard = accountSecurityGuard ?? throw new ArgumentNullException(nameof(accountSecurityGuard));
        _timeProvider = dependencies.TimeProvider ?? TimeProvider.System;
        _securityEvents = new SecurityEventEmitter(dependencies.SecurityEventSink, _timeProvider);
        _securityEventSummaryRepository = dependencies.SecurityEventSummaryRepository;
        _mfaPolicyEvaluator = dependencies.MfaPolicyEvaluator ?? new MfaPolicyEvaluator();
        _providerRegistry = dependencies.ProviderRegistry;
        _totpProvider = dependencies.TotpOptions?.Value.ProviderKey ?? TotpOptions.DefaultProviderKey;
        _recoveryCodeProvider = dependencies.RecoveryCodeOptions?.Value.ProviderKey ?? new AuthenticationProviderKey(ProviderType.RecoveryCode, "RecoveryCode");
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> DisableUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var user = await GetUserInRequestedTenantAsync(userId, request.Tenant, cancellationToken);
        if (user == null)
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserDisabled, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        var changed = user.IsActive;
        if (changed)
        {
            var guardResult = await _accountSecurityGuard.CanDisableUserAsync(user, request, cancellationToken);
            if (!guardResult.Succeeded)
            {
                await RecordFailureAsync(AshlarSecurityEventTypes.UserDisabled, userId, request, guardResult.FailureCode?.Value ?? AshlarFailureCodes.ValidationError.Value, cancellationToken);
                return Result.Failure<AccountSecurityOperationResult>(guardResult.FailureDetails ?? new AshlarFailure(AshlarFailureCodes.ValidationError));
            }

            await _userRepository.UpdateUserAsync(CloneUser(user, isActive: false), cancellationToken);
        }

        var revoked = await _sessionService.RevokeSessionsForUserAsync(userId, request.Reason ?? AdminReason, request.Tenant, request.Audit, cancellationToken);
        var result = new AccountSecurityOperationResult(userId, changed, SessionsRevoked: revoked);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserDisabled, result, request, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> ReactivateUserAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var user = await GetUserInRequestedTenantAsync(userId, request.Tenant, cancellationToken);
        if (user == null)
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserReactivated, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        var changed = !user.IsActive;
        if (changed)
        {
            await _userRepository.UpdateUserAsync(CloneUser(user, isActive: true), cancellationToken);
        }

        var result = new AccountSecurityOperationResult(userId, changed);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserReactivated, result, request, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> RevokeSessionsAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);
        var user = await GetUserInRequestedTenantAsync(userId, request.Tenant, cancellationToken);
        if (user == null)
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.SessionsRevokedForUser, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        var revoked = await _sessionService.RevokeSessionsForUserAsync(userId, request.Reason ?? AdminReason, request.Tenant, request.Audit, cancellationToken);
        return Result.Success(new AccountSecurityOperationResult(userId, SessionsRevoked: revoked));
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> RevokeCredentialsAsync(Guid userId, AuthenticationProviderKey provider, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        ValidateProvider(provider);
        request = RequireAudit(request);

        var user = await GetUserInRequestedTenantAsync(userId, request.Tenant, cancellationToken);
        if (user == null)
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserCredentialsRevoked, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken, provider);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var revoked = await _credentialRepository.RevokeCredentialsAsync(userId, provider.Type, provider.Name, cancellationToken);
        var result = new AccountSecurityOperationResult(userId, CredentialsRevoked: revoked);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserCredentialsRevoked, result, request, ct, provider));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<AccountSecurityOperationResult>> ResetMfaAsync(Guid userId, AccountSecurityOperationRequest request, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request = RequireAudit(request);

        var user = await GetUserInRequestedTenantAsync(userId, request.Tenant, cancellationToken);
        if (user == null)
        {
            await RecordFailureAsync(AshlarSecurityEventTypes.UserMfaReset, userId, request, AshlarFailureCodes.UserNotFound.Value, cancellationToken);
            return Result.Failure<AccountSecurityOperationResult>(AshlarFailureCodes.UserNotFound);
        }

        await using var transaction = await _transactionProvider.BeginTransactionAsync(cancellationToken);
        var revoked = await _credentialRepository.RevokeCredentialsAsync(userId, _totpProvider.Type, _totpProvider.Name, cancellationToken);
        revoked += await _credentialRepository.RevokeCredentialsAsync(userId, _recoveryCodeProvider.Type, _recoveryCodeProvider.Name, cancellationToken);
        var result = new AccountSecurityOperationResult(userId, CredentialsRevoked: revoked);
        transaction.OnCommitted(ct => RecordSuccessAsync(AshlarSecurityEventTypes.UserMfaReset, result, request, ct));

        await transaction.CommitAsync(cancellationToken);
        return Result.Success(result);
    }

    /// <inheritdoc />
    public async Task<Result<UserSecurityPosture>> GetUserSecurityPostureAsync(Guid userId, UserSecurityPostureRequest? request = null, CancellationToken cancellationToken = default)
    {
        ValidateUserId(userId);
        request ??= new UserSecurityPostureRequest();

        var user = await GetUserInRequestedTenantAsync(userId, request.Tenant, cancellationToken);
        if (user == null)
        {
            return Result.Failure<UserSecurityPosture>(AshlarFailureCodes.UserNotFound);
        }

        var credentials = await _credentialRepository.ListCredentialsForUserAsync(userId, activeOnly: false, cancellationToken);
        var sessions = await _sessionService.ListSessionsForUserAsync(userId, new ListAuthenticationSessionsRequest { ActiveOnly = true }, cancellationToken);
        int? eventCount = null;
        if (_securityEventSummaryRepository != null && request.RecentSecurityEventWindow is { } window)
        {
            eventCount = await _securityEventSummaryRepository.CountSecurityEventsForUserAsync(userId, _timeProvider.GetUtcNow().Subtract(window), cancellationToken);
        }

        var now = _timeProvider.GetUtcNow();
        var inventory = credentials
            .Select(ClassifyCredential)
            .OrderBy(item => item.DisplayName, StringComparer.Ordinal)
            .ThenBy(item => item.CreatedAt)
            .ToList()
            .AsReadOnly();

        var primaryCredentialItems = inventory
            .Where(item => item.IsPrimaryCredential && item.IsAvailable)
            .ToList();
        AddEmailSignInIfAvailable(primaryCredentialItems, user, now);
        var primaryCredentials = primaryCredentialItems
            .AsReadOnly();
        var factors = CreateAdditionalVerificationFactors(inventory);
        var policyEvaluation = await _mfaPolicyEvaluator.EvaluateAsync(user, new AuthenticationContext(UserId: user.Id, TenantId: request.Tenant?.TenantId), cancellationToken);
        var policy = CreatePolicyPosture(policyEvaluation, factors);

        var posture = new UserSecurityPosture(
            userId,
            user.IsActive,
            user.EmailVerifiedAt.HasValue,
            user.IsActive && primaryCredentials.Count > 0 && !policy.IsLockedOutByPolicy,
            primaryCredentials,
            factors,
            policy,
            inventory,
            sessions.Count,
            eventCount);

        return Result.Success(posture);
    }

    private static AccountSecurityOperationRequest RequireAudit(AccountSecurityOperationRequest? request)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request), "Admin account security operations require audit metadata.");
        }

        return request;
    }

    private static void ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
        {
            throw new ArgumentException("User ID cannot be empty.", nameof(userId));
        }
    }

    private static void ValidateProvider(AuthenticationProviderKey provider)
    {
        if (provider.Type == default || string.IsNullOrWhiteSpace(provider.Name))
        {
            throw new ArgumentException("Provider key must be fully initialized.", nameof(provider));
        }
    }

    private static bool IsInRequestedTenant(IUser user, TenantContext? tenant)
    {
        if (tenant == null)
        {
            return true;
        }

        if (user is not ITenantUser tenantUser)
        {
            return false;
        }

        return tenantUser.TenantId == tenant.TenantId;
    }

    private async Task<IUser?> GetUserInRequestedTenantAsync(Guid userId, TenantContext? tenant, CancellationToken cancellationToken)
    {
        var user = await _userRepository.GetUserByIdAsync(userId, cancellationToken);
        return user != null && IsInRequestedTenant(user, tenant) ? user : null;
    }

    private CredentialPostureItem ClassifyCredential(UserCredential credential)
    {
        var provider = new AuthenticationProviderKey(credential.ProviderType, credential.ProviderName);
        var registeredProvider = GetRegisteredProvider(provider);
        var factorType = GetFactorType(registeredProvider);
        var isPrimary = registeredProvider != null && AuthenticationProviderCapabilities.IsPrimary(registeredProvider);
        var isAdditionalVerification = factorType != null;
        var purpose = CredentialPosturePurpose.Unknown;
        if (isPrimary)
        {
            purpose = CredentialPosturePurpose.Primary;
        }
        else if (isAdditionalVerification)
        {
            purpose = CredentialPosturePurpose.AdditionalVerification;
        }

        return new CredentialPostureItem(
            credential.Id,
            provider,
            GetDisplayName(provider, factorType),
            purpose,
            factorType,
            isPrimary,
            isAdditionalVerification,
            credential.IsAvailable(_timeProvider.GetUtcNow()),
            IsRevocable(provider),
            IsResettable(provider),
            credential.CreatedAt,
            credential.LastUsedAt,
            credential.ExpiresAt,
            credential.Status);
    }

    private static ReadOnlyCollection<AdditionalVerificationFactorPosture> CreateAdditionalVerificationFactors(IReadOnlyList<CredentialPostureItem> inventory)
    {
        return inventory
            .Where(item => item.IsAdditionalVerificationFactor && item.FactorType != null)
            .GroupBy(item => item.FactorType!, StringComparer.OrdinalIgnoreCase)
            .Select(group => new AdditionalVerificationFactorPosture(
                NormalizeFactorType(group.Key),
                GetFactorDisplayName(group.Key),
                group.Any(),
                group.Any(item => item.IsAvailable),
                group.Select(item => item.Provider).Distinct().ToList().AsReadOnly()))
            .OrderBy(factor => factor.DisplayName, StringComparer.Ordinal)
            .ToList()
            .AsReadOnly();
    }

    private static AccountSecurityPolicyPosture CreatePolicyPosture(
        MfaPolicyEvaluation evaluation,
        IReadOnlyList<AdditionalVerificationFactorPosture> configuredFactors)
    {
        var required = NormalizeFactors(evaluation.Requirement?.RequiredFactors);
        var configured = configuredFactors
            .Where(factor => factor.IsUsable)
            .Select(factor => NormalizeFactorType(factor.FactorType))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var missing = evaluation.IsMfaRequired
            ? required.Where(factor => !configured.Contains(factor)).ToList()
            : [];
        var hasUsableFactor = configured.Count > 0;
        var isReady = !evaluation.IsMfaRequired || (missing.Count == 0 && hasUsableFactor);

        return new AccountSecurityPolicyPosture(
            evaluation.IsMfaRequired,
            required.AsReadOnly(),
            [],
            hasUsableFactor,
            isReady,
            missing.AsReadOnly(),
            missing.Select(GetFactorDisplayName).ToList().AsReadOnly(),
            evaluation.IsMfaRequired && !isReady);
    }

    private IAuthenticationProvider? GetRegisteredProvider(AuthenticationProviderKey provider)
    {
        return _providerRegistry?.TryGetProvider(provider, out var registeredProvider) == true
            ? registeredProvider
            : null;
    }

    private static void AddEmailSignInIfAvailable(List<CredentialPostureItem> primaryCredentials, IUser user, DateTimeOffset now)
    {
        if (!string.IsNullOrWhiteSpace(user.Email)
            && !primaryCredentials.Any(item => item.Provider.Type == ProviderType.EmailCode || item.Provider.Type == ProviderType.MagicLink))
        {
            primaryCredentials.Add(new CredentialPostureItem(
                Guid.Empty,
                AuthenticationProviderKey.MagicLink,
                "Email sign-in",
                CredentialPosturePurpose.Primary,
                null,
                true,
                false,
                user.IsActive,
                false,
                false,
                now,
                null,
                null,
                user.IsActive ? CredentialStatus.Active : CredentialStatus.Revoked));
        }
    }

    private bool IsTotpProvider(AuthenticationProviderKey provider)
    {
        return provider == _totpProvider
            || (provider.Type == ProviderType.Mfa && string.Equals(provider.Name, "totp", StringComparison.OrdinalIgnoreCase));
    }

    private bool IsRecoveryCodeProvider(AuthenticationProviderKey provider)
    {
        return provider == _recoveryCodeProvider || provider.Type == ProviderType.RecoveryCode;
    }

    private static string? GetFactorType(IAuthenticationProvider? provider)
    {
        if (provider is not ISecondaryAuthenticationFactorProvider factorProvider)
        {
            return null;
        }

        return NormalizeFactorType(factorProvider.FactorType);
    }

    private static string GetDisplayName(AuthenticationProviderKey provider, string? factorType)
    {
        if (factorType != null)
        {
            return GetFactorDisplayName(factorType);
        }

        if (provider.Type == ProviderType.Local)
        {
            return "Password";
        }

        if (provider.Type == ProviderType.EmailCode || provider.Type == ProviderType.MagicLink)
        {
            return "Email sign-in";
        }

        if (provider.Type == ProviderType.OAuth || provider.Type == ProviderType.Oidc || provider.Type == ProviderType.Saml2)
        {
            return string.Equals(provider.Name, provider.Type.Value, StringComparison.OrdinalIgnoreCase)
                ? "External sign-in"
                : provider.Name;
        }

        return provider.Name;
    }

    private static string GetFactorDisplayName(string factorType)
    {
        return NormalizeFactorType(factorType) switch
        {
            AuthenticationFactorTypes.Totp => "Authenticator app",
            AuthenticationFactorTypes.RecoveryCode => "Recovery codes",
            AuthenticationFactorTypes.Passkey => "Passkeys",
            var value => value
        };
    }

    private static List<string> NormalizeFactors(IEnumerable<string>? factors)
    {
        return factors?
            .Where(factor => !string.IsNullOrWhiteSpace(factor))
            .Select(NormalizeFactorType)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(factor => factor, StringComparer.Ordinal)
            .ToList() ?? [];
    }

    private static string NormalizeFactorType(string factorType)
    {
        return factorType.Trim().Replace('-', '_').ToLowerInvariant();
    }

    private static bool IsRevocable(AuthenticationProviderKey provider)
    {
        return provider.Type != ProviderType.Internal;
    }

    private bool IsResettable(AuthenticationProviderKey provider)
    {
        return IsTotpProvider(provider) || IsRecoveryCodeProvider(provider);
    }

    private static AshlarUser CloneUser(IUser user, bool isActive)
    {
        return new AshlarUser
        {
            Id = user.Id,
            Email = user.Email,
            Name = user.Name,
            IsActive = isActive,
            TenantId = (user as ITenantUser)?.TenantId,
            EmailVerifiedAt = user.EmailVerifiedAt
        };
    }

    private Task RecordFailureAsync(string eventType, Guid userId, AccountSecurityOperationRequest request, string failureReason, CancellationToken cancellationToken, AuthenticationProviderKey? provider = null)
    {
        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Failure,
            UserId = userId,
            TenantId = request.Tenant?.TenantId,
            Audit = request.Audit,
            Provider = provider,
            FailureReason = failureReason
        }, cancellationToken);
    }

    private Task RecordSuccessAsync(string eventType, AccountSecurityOperationResult result, AccountSecurityOperationRequest request, CancellationToken cancellationToken, AuthenticationProviderKey? provider = null)
    {
        var properties = new Dictionary<string, string>
        {
            ["user_changed"] = result.UserChanged ? "true" : "false",
            ["sessions_revoked"] = result.SessionsRevoked.ToString(CultureInfo.InvariantCulture),
            ["credentials_revoked"] = result.CredentialsRevoked.ToString(CultureInfo.InvariantCulture)
        };
        if (request.Reason != null)
        {
            properties["reason"] = request.Reason;
        }

        return _securityEvents.RecordAsync(new SecurityEventDescriptor
        {
            EventType = eventType,
            Outcome = SecurityEventOutcomes.Success,
            UserId = result.UserId,
            TenantId = request.Tenant?.TenantId,
            Audit = request.Audit,
            Provider = provider,
            Properties = properties
        }, cancellationToken);
    }
}

/// <summary>
/// Dependencies for <see cref="AccountSecurityService"/>.
/// </summary>
/// <param name="TimeProvider">The time provider value.</param>
/// <param name="SecurityEventSink">The security event sink value.</param>
/// <param name="SecurityEventSummaryRepository">The security event summary repository value.</param>
/// <param name="TotpOptions">The TOTP options value.</param>
/// <param name="RecoveryCodeOptions">The recovery code options value.</param>
/// <param name="MfaPolicyEvaluator">The MFA policy evaluator value.</param>
/// <param name="ProviderRegistry">The authentication provider registry.</param>
public sealed record AccountSecurityServiceDependencies(
    TimeProvider? TimeProvider = null,
    ISecurityEventSink? SecurityEventSink = null,
    IUserSecurityEventSummaryRepository? SecurityEventSummaryRepository = null,
    IOptions<TotpOptions>? TotpOptions = null,
    IOptions<RecoveryCodeOptions>? RecoveryCodeOptions = null,
    IMfaPolicyEvaluator? MfaPolicyEvaluator = null,
    IAuthenticationProviderRegistry? ProviderRegistry = null);
